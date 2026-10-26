// intended_set.go — userspace serialization of spec.IntendedSet into
// LPM trie keys for the slice-22 file_open probe.
//
// The wire layout must match struct lpm_key in bpf/file_open/file_open.bpf.c:
//
//   struct lpm_key {
//       __u32 prefixlen;
//       char  path[256];
//   };
//
// Encoding contract for entries in the trie:
//
//   - Each entry is exact-match: path bytes followed by an explicit '\0',
//     prefixlen = (len(path) + 1) * 8.
//   - The trailing NUL is what makes the LPM lookup strict — without it,
//     "/proc/sysrq-trig" (a hypothetical shorter masked path) would falsely
//     match a "/proc/sysrq-trigger" write, because LPM compares bits and
//     doesn't understand path-segment boundaries. The NUL byte at the
//     stored entry's last position only matches a NUL byte at the lookup
//     key's corresponding position (which bpf_d_path always writes after
//     the resolved path).
//
// Subtree-match entries (e.g. "mask /proc entirely") are NOT supported in
// slice 22 — the IntendedSet builder only produces specific paths today.
// When that changes, this serializer needs a second encoding: trailing
// slash, no NUL, prefixlen = len(path) * 8.

package watch

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
)

// LPMPathMax matches TARGET_MAX in bpf/file_open/file_open.bpf.c. If
// either side changes this, both must.
const LPMPathMax = 256

// PolicyClass values stored as the LPM trie's value byte. Must match
// POLICY_* macros in bpf/file_open/file_open.bpf.c.
type PolicyClass uint8

const (
	PolicyUnknown  PolicyClass = 0 // emitted on truncation; not a stored class
	PolicyMasked   PolicyClass = 1
	PolicyReadOnly PolicyClass = 2
)

// String returns a stable lowercase name for logging / event rendering.
func (p PolicyClass) String() string {
	switch p {
	case PolicyMasked:
		return "masked"
	case PolicyReadOnly:
		return "readonly"
	case PolicyUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("policy(%d)", uint8(p))
	}
}

// lpmKey is the Go-side counterpart of struct lpm_key. Field order, types,
// and array length must match the BPF struct exactly.
type lpmKey struct {
	Prefixlen uint32
	Path      [LPMPathMax]byte
}

// IntendedSetEntries returns the (path, class) pairs from `intended` that
// the file_open probe should store. Today: every Entry of Kind=masked or
// Kind=readonly. Mounts (Kind=mounted) are explicit mount points the
// container is supposed to write to and never produce a violation, so
// they're excluded from the LPM trie.
func IntendedSetEntries(intended *spec.IntendedSet) []IntendedSetEntry {
	if intended == nil {
		return nil
	}
	out := make([]IntendedSetEntry, 0, len(intended.Entries))
	for path, e := range intended.Entries {
		var cls PolicyClass
		switch e.Kind {
		case spec.KindMasked:
			cls = PolicyMasked
		case spec.KindReadOnly:
			cls = PolicyReadOnly
		default:
			continue
		}
		out = append(out, IntendedSetEntry{Path: path, Class: cls})
	}
	return out
}

// IntendedSetEntry is one (path, class) pair destined for the LPM trie.
type IntendedSetEntry struct {
	Path  string
	Class PolicyClass
}

// populateIntendedSetMap writes every entry in `entries` to the given
// inner LPM trie map. The map should be freshly created (or known-empty);
// duplicate writes are tolerated by BPF map semantics but produce no
// useful behavior.
//
// Paths longer than LPMPathMax - 1 (255 chars; one byte for the trailing
// NUL) are rejected — they wouldn't fit in the trie key, and silently
// truncating them would cause unrelated paths to share a prefix and
// trigger false positives in the probe.
func populateIntendedSetMap(inner *ebpf.Map, entries []IntendedSetEntry) error {
	for _, e := range entries {
		if len(e.Path) >= LPMPathMax {
			return fmt.Errorf("intended-set path %q is %d bytes; max is %d (LPMPathMax - 1 for trailing NUL)",
				e.Path, len(e.Path), LPMPathMax-1)
		}
		var key lpmKey
		copy(key.Path[:], e.Path)
		key.Path[len(e.Path)] = 0 // explicit NUL guard — see file header
		// prefixlen is in bits, including the NUL.
		key.Prefixlen = uint32((len(e.Path) + 1) * 8)
		value := uint8(e.Class)
		if err := inner.Put(&key, &value); err != nil {
			return fmt.Errorf("populate trie with %q (%s): %w", e.Path, e.Class, err)
		}
	}
	return nil
}
