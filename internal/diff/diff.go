// Package diff compares the operator-declared IntendedSet against the
// container's runtime-observed ObservedSet and produces a typed list of
// deviations.
//
// Implemented deviation classes:
//
//   - WritableDrift: a path declared masked or read-only in the OCI spec
//     was observed as writable inside the container.
//   - OutOfPolicyRedirect: a symlink whose lexically-resolved target lands
//     on a path the OCI spec declared masked. The intuition: a symlink
//     creates a second name for a target the operator deliberately tried to
//     hide. This is the shape of CVE-2024-21626 (symlinks/fd leaks pointing
//     into paths that should be inaccessible).
//   - CgroupDelegationExposure: a writable file under /sys/fs/cgroup whose
//     write would reach outside the container's delegated subtree. See
//     design/architecture.md.
//
// Runtime watcher events add PostStartRemount and RuntimeWrite; see runtime_write.go.
//
// Diff also returns Annotations — info-level observations about safe-but-
// noteworthy setups (e.g. a properly delegated cgroup subtree). Annotations
// prove the verifier understood the setup; they are not failures.
//
// The differ is a pure function: same inputs always produce the same outputs.
// It does not enter namespaces and does not touch the filesystem.
package diff

import (
	"path"
	"sort"
	"strings"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
)

// Class names the type of deviation. Stable strings: external consumers
// (dashboards, log aggregators) will match on these.
type Class string

const (
	ClassWritableDrift       Class = "WritableDrift"
	ClassOutOfPolicyRedirect Class = "OutOfPolicyRedirect"
	ClassPostStartRemount    Class = "PostStartRemount" // eBPF watcher; runtime; see runtime_write.go
)

// Deviation is one violation of the intended-vs-observed contract.
//
// Observed and Intended are typed per-class structs (see WritableDriftObserved
// and WritableDriftIntended). They are kept as `any` here so the same
// envelope can carry every class; renderers may type-switch on Class.
type Deviation struct {
	Class    Class  `json:"class"`
	Path     string `json:"path"`
	Observed any    `json:"observed"`
	Intended any    `json:"intended"`
	// Rule names the policy entry that flagged (or, in a later slice, allowed)
	// this deviation. Empty when no policy was consulted.
	Rule string `json:"rule,omitempty"`
}

// WritableDriftObserved captures what the verifier actually saw at a path
// that was supposed to be masked or read-only.
type WritableDriftObserved struct {
	Mode     string `json:"mode"`
	Writable bool   `json:"writable"`
	MountID  int    `json:"mount_id,omitempty"`
}

// WritableDriftIntended captures what the OCI spec said about the path.
type WritableDriftIntended struct {
	Kind string `json:"kind"` // "masked" | "readonly"
}

// OutOfPolicyRedirectObserved captures the symlink and its raw target.
type OutOfPolicyRedirectObserved struct {
	LinkTarget     string `json:"link_target"`     // raw value of the link
	ResolvedTarget string `json:"resolved_target"` // lexically resolved absolute path
}

// OutOfPolicyRedirectIntended captures what the resolved target was supposed
// to be — the IntendedSet entry at the resolved target.
type OutOfPolicyRedirectIntended struct {
	TargetKind string `json:"target_kind"` // "masked" today; "readonly" deliberately not flagged in v0
}

// Report is the top-level JSON envelope per container.
type Report struct {
	ContainerID string       `json:"container_id"`
	InitPID     int          `json:"init_pid,omitempty"`
	Deviations  []Deviation  `json:"deviations"`
	Annotations []Annotation `json:"annotations,omitempty"`
}

// Result bundles the two outputs of a differ run.
type Result struct {
	Deviations  []Deviation
	Annotations []Annotation
}

// Diff compares an IntendedSet against an ObservedSet and returns the list
// of deviations and any info-level annotations. Both slices are sorted for
// stable output.
//
// nil inputs are tolerated and produce an empty result; this matches the
// CLI behavior where partial data is preferable to a crash.
func Diff(intended *spec.IntendedSet, observed *observe.ObservedSet) Result {
	var r Result
	if intended == nil || observed == nil {
		return r
	}

	r.Deviations = append(r.Deviations, writableDrift(intended, observed)...)
	r.Deviations = append(r.Deviations, outOfPolicyRedirect(intended, observed)...)
	cgroupDevs, cgroupAnns := cgroupDelegation(observed)
	r.Deviations = append(r.Deviations, cgroupDevs...)
	r.Annotations = append(r.Annotations, cgroupAnns...)

	sort.Slice(r.Deviations, func(i, j int) bool {
		if r.Deviations[i].Class != r.Deviations[j].Class {
			return r.Deviations[i].Class < r.Deviations[j].Class
		}
		return r.Deviations[i].Path < r.Deviations[j].Path
	})
	sort.Slice(r.Annotations, func(i, j int) bool {
		if r.Annotations[i].Kind != r.Annotations[j].Kind {
			return r.Annotations[i].Kind < r.Annotations[j].Kind
		}
		return r.Annotations[i].Path < r.Annotations[j].Path
	})
	return r
}

func writableDrift(intended *spec.IntendedSet, observed *observe.ObservedSet) []Deviation {
	var out []Deviation
	for p, entry := range intended.Entries {
		switch entry.Kind {
		case spec.KindMasked, spec.KindReadOnly:
			// Only the locked-down kinds participate in writable-drift.
			// Mounted paths derive their writability from the mount
			// options the operator chose, so they are not a deviation
			// just because they are writable.
		default:
			continue
		}

		obs, ok := observed.Entries[p]
		if !ok {
			continue
		}
		if !obs.Writable {
			continue
		}

		out = append(out, Deviation{
			Class: ClassWritableDrift,
			Path:  p,
			Observed: WritableDriftObserved{
				Mode:     obs.Mode,
				Writable: obs.Writable,
				MountID:  obs.MountID,
			},
			Intended: WritableDriftIntended{Kind: string(entry.Kind)},
		})
	}
	return out
}

// outOfPolicyRedirect walks every symlink in ObservedSet, resolves the
// target lexically, and flags those whose resolved path is declared masked
// in IntendedSet — i.e. the symlink creates a second name for a path the
// operator deliberately tried to hide.
//
// v0 scope choices:
//
//   - Only flag against KindMasked targets. A redirect to a readonly target
//     does not bypass anything (the readonly bind survives the dereference).
//   - Skip self-loop symlinks (link path == resolved target).
//   - Skip when the symlink itself sits at a masked or readonly path: that
//     entry will already be flagged by WritableDrift if it matters.
func outOfPolicyRedirect(intended *spec.IntendedSet, observed *observe.ObservedSet) []Deviation {
	var out []Deviation
	for linkPath, obs := range observed.Entries {
		if !obs.IsSymlink || obs.LinkTarget == "" {
			continue
		}
		resolved := resolveLink(linkPath, obs.LinkTarget)
		if resolved == linkPath {
			continue
		}
		// Don't double-flag a link whose own entry is already covered by
		// a more-specific intended-set rule.
		if e, ok := intended.Entries[linkPath]; ok && (e.Kind == spec.KindMasked || e.Kind == spec.KindReadOnly) {
			continue
		}
		// Find the most specific IntendedSet entry covering `resolved`.
		entry, ok := coveringIntendedEntry(intended, resolved)
		if !ok {
			continue
		}
		if entry.Kind != spec.KindMasked {
			continue
		}
		out = append(out, Deviation{
			Class: ClassOutOfPolicyRedirect,
			Path:  linkPath,
			Observed: OutOfPolicyRedirectObserved{
				LinkTarget:     obs.LinkTarget,
				ResolvedTarget: resolved,
			},
			Intended: OutOfPolicyRedirectIntended{
				TargetKind: string(entry.Kind),
			},
		})
	}
	return out
}

// resolveLink lexically resolves a symlink target relative to its containing
// directory. Absolute targets are returned as-is (cleaned). Relative targets
// are joined with the directory of linkPath and cleaned.
//
// This is *lexical* — we do not follow further symlinks in the resolved path
// and we do not check the filesystem. CVE-2024-21626 was a lexical leak too:
// the dangerous redirect was visible just from the symlink target text.
func resolveLink(linkPath, target string) string {
	if path.IsAbs(target) {
		return path.Clean(target)
	}
	return path.Clean(path.Join(path.Dir(linkPath), target))
}

// coveringIntendedEntry returns the most specific IntendedSet entry whose
// path equals `p` or is a prefix directory of `p`. False if no entry matches.
func coveringIntendedEntry(intended *spec.IntendedSet, p string) (spec.Entry, bool) {
	var best spec.Entry
	var bestLen int
	for ep, e := range intended.Entries {
		if ep == p || strings.HasPrefix(p, ep+"/") {
			if len(ep) > bestLen {
				best = e
				bestLen = len(ep)
			}
		}
	}
	if bestLen == 0 {
		return spec.Entry{}, false
	}
	return best, true
}
