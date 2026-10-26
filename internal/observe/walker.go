package observe

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// walk traverses the in-namespace filesystem under `root` and returns one
// Observed entry per surviving filesystem entry. It silently skips entries
// it cannot read (e.g. a process that exited mid-walk).
//
// We deliberately do not follow symlinks: every stat is an lstat, every
// link target is read raw via Readlink, and we never open a file for write.
func walk(root string, mounts []MountInfo) map[string]Observed {
	out := map[string]Observed{}
	idx := indexMounts(mounts)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Don't propagate — /proc and /sys entries can vanish between
			// readdir and stat. Skipping is the correct behavior.
			return nil
		}
		if path != root && shouldSkip(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// d.Info() returns the lstat result for the entry. We never Stat,
		// which would follow symlinks.
		info, err := d.Info()
		if err != nil {
			return nil
		}
		obs := Observed{
			Path: path,
			Mode: info.Mode().String(),
		}
		if info.Mode()&os.ModeSymlink != 0 {
			obs.IsSymlink = true
			if target, lerr := os.Readlink(path); lerr == nil {
				obs.LinkTarget = target
			}
		}
		obs.Writable, obs.MountID = writability(path, info, idx)
		out[path] = obs
		return nil
	})
	return out
}

// shouldSkip returns true for paths under /proc or /sys that are not
// interesting for the verifier and/or known to misbehave under a recursive
// walk.
//
// Under /proc:
//   - /proc/<digits>/ — per-process trees. Too noisy, churn during walk; the
//     verifier's job is the structural view, not running PIDs.
//   - /proc/kcore     — opening or stating it has historically been slow or
//     hung kernels; we don't need it for masked-path checks.
//   - /proc/kpage*    — large, slow to read, not part of the contract.
//
// Under /sys:
//   - /sys/kernel/debug — debugfs is usually not mounted in containers, but
//     if it is, walking it is slow and exposes kernel internals we don't model.
//   - /sys/kernel/tracing — tracefs, same concerns as debugfs.
//   - /sys/firmware/efi/efivars — EFI vars can be enormous and reading them
//     has caused kernel issues historically.
//   - /sys/kernel/security — securityfs internals; LSM-specific.
func shouldSkip(path string) bool {
	if strings.HasPrefix(path, "/proc/") {
		return shouldSkipProc(path)
	}
	if strings.HasPrefix(path, "/sys/") {
		return shouldSkipSys(path)
	}
	return false
}

func shouldSkipProc(path string) bool {
	rel := strings.TrimPrefix(path, "/proc/")
	first := rel
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		first = rel[:i]
	}
	if isAllDigits(first) {
		return true
	}
	switch path {
	case "/proc/kcore",
		"/proc/kpagecount",
		"/proc/kpageflags",
		"/proc/kpagecgroup":
		return true
	}
	return false
}

func shouldSkipSys(path string) bool {
	// Match exact path or its descendants (path + "/").
	for _, prefix := range sysSkipPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// sysSkipPrefixes lists subtrees under /sys that the walker will not enter.
// See shouldSkip godoc for the rationale.
var sysSkipPrefixes = []string{
	"/sys/kernel/debug",
	"/sys/kernel/tracing",
	"/sys/kernel/security",
	"/sys/firmware/efi/efivars",
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// writability infers whether `path` is writable from the perspective of a
// process inside the container, without ever opening it for write.
//
// "Writable" here means *security-relevant* writability: a write to this path
// would have an effect the operator should care about. We answer "no" when:
//
//   - the containing mount is `ro`; or
//   - the entry is a character or block device. Regular /proc and /sys entries
//     are never devices, so a device here is the result of a masking bind
//     mount (runc realizes file masks by bind-mounting /dev/null over the
//     path; the entry appears as crw-rw-rw- with the mount itself rw, but
//     writes go to the void — masking is doing its job).
//
// Otherwise we report whether any of u/g/o has the write bit set. DAC and LSM
// checks may still deny a given UID at runtime; the verifier reports the
// upper bound.
func writability(path string, info fs.FileInfo, idx *mountIndex) (bool, int) {
	m := idx.containing(path)
	var mid int
	if m != nil {
		mid = m.MountID
		if m.ReadOnly() {
			return false, mid
		}
	}
	if info.Mode()&(os.ModeDevice|os.ModeCharDevice) != 0 {
		return false, mid
	}
	// 0222 = w-bit in user/group/other.
	return info.Mode().Perm()&0222 != 0, mid
}
