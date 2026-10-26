// translate.go — convert BPF event structs into diff.Deviation values
// that share the same JSON schema as the static-scan output. This is
// where the talk's "same schema, same policy, different time" claim
// actually pays off: a renderer or policy filter cannot tell whether
// it's looking at a scan deviation or a watch deviation.

package watch

import (
	"fmt"
	"time"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

// nowFunc is the time source for OccurredAt stamps. Tests overwrite
// it to get deterministic timestamps; production reads time.Now.
var nowFunc = func() time.Time { return time.Now().UTC() }

// commToString trims a kernel-padded comm field to its meaningful
// prefix. The BPF event helpers already null-pad; this is defensive
// for the rare case where the kernel writes a non-null-terminated
// 16-byte string.
func commToString(b [16]byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b[:])
}

// SBMountToDeviation turns one sb_mount ringbuf event into a
// diff.Deviation of class PostStartRemount. `containerID` is
// stamped on the resulting Deviation indirectly via the caller
// (Deviation has no container_id field; the surrounding Report
// carries it).
//
// Truncated events (kernel couldn't resolve the mount target) are
// still translated — userspace consumers want the cgroup + actor
// even when the path is unknown, and the Truncated flag tells them
// to re-scan.
func SBMountToDeviation(ev SBMountEvent) diff.Deviation {
	target := ev.TargetString()
	path := target
	if path == "" {
		path = "(unresolved)"
	}
	return diff.Deviation{
		Class: diff.ClassPostStartRemount,
		Path:  path,
		Observed: diff.PostStartRemountObserved{
			CgroupID:   ev.CgroupID,
			ActorPID:   ev.PID,
			ActorTGID:  ev.TGID,
			ActorComm:  commToString(ev.Comm),
			OccurredAt: nowFunc().Format(time.RFC3339Nano),
			Truncated:  ev.Truncated(),
		},
		// Intended is intentionally a zero PostStartRemountIntended;
		// see runtime_write.go for the rationale. The static scan
		// doesn't have a per-mount expectation to compare against,
		// so the policy filter handles the whole class through the
		// `class:` keyword rather than per-path matching.
		Intended: diff.PostStartRemountIntended{},
	}
}

// FileOpenToDeviation turns one file_open ringbuf event into a
// diff.Deviation of class RuntimeWrite. The PolicyClass byte from
// the LPM trie value is mapped back to the spec.Kind name the
// IntendedSet originally carried — that's the field the policy
// filter consults to decide allow vs deny.
func FileOpenToDeviation(ev FileOpenEvent) diff.Deviation {
	target := ev.TargetString()
	path := target
	if path == "" {
		path = "(unresolved)"
	}
	classStr := ev.Class().String()
	return diff.Deviation{
		Class: diff.ClassRuntimeWrite,
		Path:  path,
		Observed: diff.RuntimeWriteObserved{
			CgroupID:   ev.CgroupID,
			ActorPID:   ev.PID,
			ActorTGID:  ev.TGID,
			ActorComm:  commToString(ev.Comm),
			OccurredAt: nowFunc().Format(time.RFC3339Nano),
			Truncated:  ev.Truncated(),
		},
		Intended: diff.RuntimeWriteIntended{
			Class: classStr,
		},
	}
}

// describe returns a short human-friendly summary of an event, used
// in error messages and the watch subcommand's stderr trace. Not part
// of the wire schema.
func describe(d diff.Deviation) string {
	return fmt.Sprintf("%s %s", d.Class, d.Path)
}
