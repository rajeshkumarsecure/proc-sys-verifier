package diff

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
)

// ClassCgroupDelegationExposure flags a writable file under /sys/fs/cgroup
// whose write would reach the container's parent or sibling cgroups —
// either because the cgroup mount's `root` is broader than the container's
// own cgroup path, or (annotated, not promoted) because the container shares
// the host's cgroup namespace.
const ClassCgroupDelegationExposure Class = "CgroupDelegationExposure"

// CgroupDelegationExposureObserved is the per-class typed payload for the
// renderer and JSON consumers. See design/architecture.md.
type CgroupDelegationExposureObserved struct {
	File            string `json:"file"`
	ContainerCgroup string `json:"container_cgroup"`
	MountRoot       string `json:"mount_root"`
	MountRW         bool   `json:"mount_rw"`
	CgroupNSShared  bool   `json:"cgroup_ns_shared"`
	EffectivePath   string `json:"effective_path"`
	Effect          string `json:"effect"`
}

// CgroupDelegationExposureIntended carries the operator's "what should be
// reachable" boundary so policy rules can compare against it.
type CgroupDelegationExposureIntended struct {
	DelegatedSubtree string `json:"delegated_subtree"`
}

// AnnotationKind names a non-deviation observation worth surfacing in the
// TTY renderer. Annotations are NOT failures: they prove the verifier
// understood a safe-but-noteworthy setup.
type AnnotationKind string

const (
	// AnnotationDelegatedLeaf marks a writable cgroup file whose write
	// stays inside the container's own delegated subtree. The operator
	// asked for delegation; the kernel and runtime delivered it.
	AnnotationDelegatedLeaf AnnotationKind = "DelegatedLeaf"
)

// Annotation is an info-level note attached to the Report. Surfaced in TTY
// under a dim "context" heading; included in JSON for completeness.
type Annotation struct {
	Kind    AnnotationKind `json:"kind"`
	Path    string         `json:"path"`
	Message string         `json:"message"`
}

// cgroupDelegation classifies writable /sys/fs/cgroup/* entries into
// deviations (delegated-parent: writes escape the container's subtree) and
// annotations (delegated-leaf: writes are contained).
//
// Returns two slices because the two kinds live in different parts of the
// Report.
func cgroupDelegation(observed *observe.ObservedSet) ([]Deviation, []Annotation) {
	if observed == nil {
		return nil, nil
	}
	if observed.Cgroup.Path == "" {
		// Without the container's own cgroup path we cannot tell delegated
		// from parent. Skip silently — the rest of the report is still
		// useful.
		return nil, nil
	}

	mountByPath := indexMountsByLongestPrefix(observed.Mounts)

	var devs []Deviation
	var anns []Annotation
	for p, obs := range observed.Entries {
		if !obs.Writable {
			continue
		}
		if !strings.HasPrefix(p, "/sys/fs/cgroup/") {
			continue
		}

		mnt := mountByPath(p)
		if mnt == nil {
			// No covering mount entry — should not happen for /sys/fs/cgroup,
			// but staying defensive.
			continue
		}

		// Where in the host's cgroup tree does a write to this file land?
		// rel is the part of p past the mount point.
		rel := strings.TrimPrefix(p, mnt.MountPoint)
		effective := path.Join(mnt.Root, rel)

		delegated := isInside(effective, observed.Cgroup.Path)

		if delegated {
			anns = append(anns, Annotation{
				Kind: AnnotationDelegatedLeaf,
				Path: p,
				Message: fmt.Sprintf(
					"writable; effective host cgroup %s is inside container's delegated subtree %s",
					effective, observed.Cgroup.Path),
			})
			continue
		}

		// Not in the delegated subtree — exposure.
		effect := fmt.Sprintf("write to %s would land at host cgroup %s (outside delegated subtree %s)",
			p, effective, observed.Cgroup.Path)
		if observed.Cgroup.NamespaceShared {
			effect += "; container shares host cgroup namespace"
		}
		devs = append(devs, Deviation{
			Class: ClassCgroupDelegationExposure,
			Path:  p,
			Observed: CgroupDelegationExposureObserved{
				File:            p,
				ContainerCgroup: observed.Cgroup.Path,
				MountRoot:       mnt.Root,
				MountRW:         !mnt.ReadOnly(),
				CgroupNSShared:  observed.Cgroup.NamespaceShared,
				EffectivePath:   effective,
				Effect:          effect,
			},
			Intended: CgroupDelegationExposureIntended{
				DelegatedSubtree: observed.Cgroup.Path,
			},
		})
	}
	return devs, anns
}

// isInside reports whether `child` is `parent` or a descendant of it,
// interpreting both as cgroup paths (forward-slash, leading "/"). Root
// ("/") is the ancestor of every path.
func isInside(child, parent string) bool {
	if parent == "/" {
		return true
	}
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+"/")
}

// indexMountsByLongestPrefix returns a lookup that, for a given path,
// yields the most specific mount whose MountPoint covers it. This is a
// stand-alone helper because internal/observe's own mountIndex is unexported.
func indexMountsByLongestPrefix(mounts []observe.MountInfo) func(string) *observe.MountInfo {
	sorted := append([]observe.MountInfo(nil), mounts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return len(sorted[i].MountPoint) > len(sorted[j].MountPoint)
	})
	return func(p string) *observe.MountInfo {
		for i := range sorted {
			mp := sorted[i].MountPoint
			if mp == "/" || mp == p || strings.HasPrefix(p, mp+"/") {
				return &sorted[i]
			}
		}
		return nil
	}
}
