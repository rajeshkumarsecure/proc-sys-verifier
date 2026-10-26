// cgroup.go — userspace helpers for working with kernel cgroup IDs.
//
// The kernel identifies cgroups by an inode number (st_ino of the
// cgroup directory under /sys/fs/cgroup). That's what
// bpf_get_current_cgroup_id() returns inside a probe and what our
// watched-cgroups map keys on. The observer's Phase 2 CgroupInfo
// captures the *namespace* ID (a different identity used by the
// policy classifier); these helpers fill the gap between the two
// worlds.

package watch

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// CgroupIDFromPath returns the kernel cgroup ID for the cgroup whose
// directory is at hostPath. hostPath must be readable from the host's
// mount namespace (typically /sys/fs/cgroup/<cgroup-relative-path>).
//
// The returned ID is the value bpf_get_current_cgroup_id() will
// produce inside the kernel for any task whose cgroup membership
// includes the directory at hostPath.
func CgroupIDFromPath(hostPath string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(hostPath, &st); err != nil {
		return 0, fmt.Errorf("stat %q: %w", hostPath, err)
	}
	return st.Ino, nil
}

// CgroupIDFromObservedPath is a convenience wrapper for the common
// case where the caller has an observe.CgroupInfo whose Path field is
// the container's cgroup relative to /sys/fs/cgroup (e.g.
// "/user.slice/user-1000.slice/demo"). Composes the host path and
// stats it.
func CgroupIDFromObservedPath(cgroupRelPath string) (uint64, error) {
	if cgroupRelPath == "" {
		return 0, fmt.Errorf("empty cgroup path")
	}
	return CgroupIDFromPath("/sys/fs/cgroup" + cgroupRelPath)
}
