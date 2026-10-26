package observe

import (
	"context"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/discover"
)

// nsToEnter lists, in order, the namespace types we setns into before walking.
//
// We enter only the mount namespace. The walker needs the container's view of
// /proc and /sys, which is supplied by the mount namespace. We deliberately
// do NOT enter the pid namespace: setns(pid) only affects children of the
// caller, not the caller itself, so after entering it our /proc/self would
// still resolve in whichever pid ns we were created in — and the container's
// /proc (mounted in *its* pid ns) would not contain an entry for our host
// pid, breaking /proc/self/mountinfo lookups.
//
// We do NOT enter the user namespace: the verifier is expected to run as host
// root, which already has the capabilities required for setns(mnt).
var nsToEnter = []string{"mnt"}

// Container observes the in-container view of /proc for c and returns the
// snapshot. The caller must be running as host root (or have an equivalent
// capability set: at minimum CAP_SYS_ADMIN + CAP_SYS_PTRACE).
//
// The work runs on a dedicated OS thread that is locked for its lifetime and
// never unlocked. When the worker goroutine exits, Go disposes of the thread
// — it is not returned to the runtime's thread pool. This is the standard
// pattern for setns work and is required for correctness.
func Container(ctx context.Context, c discover.Container) (*ObservedSet, error) {
	if c.InitPID <= 0 {
		return nil, fmt.Errorf("container %q has no init pid", c.ID)
	}

	type result struct {
		set *ObservedSet
		err error
	}
	ch := make(chan result, 1) // buffered so the worker can finish even after ctx cancel.

	go func() {
		// Lock and never unlock. The thread dies with this goroutine.
		runtime.LockOSThread()
		set, err := observeLocked(c)
		ch <- result{set, err}
	}()

	select {
	case r := <-ch:
		return r.set, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// observeLocked performs the setns + walk. MUST be called on a thread that
// has been locked via runtime.LockOSThread(). MUST NOT call UnlockOSThread.
func observeLocked(c discover.Container) (*ObservedSet, error) {
	// Read the container's mountinfo via the host's view of init's
	// /proc/<pid>/mountinfo BEFORE entering the mount namespace. After
	// setns(mnt) we see the container's /proc (mounted in its own pid ns),
	// which has no entry for our host pid — /proc/self resolves to ENOENT
	// there. The host kernel emits this file as a namespace-local view, so
	// the data is the same as `cat /proc/self/mountinfo` inside.
	mountInfoPath := fmt.Sprintf("/proc/%d/mountinfo", c.InitPID)
	mounts, err := ReadMountInfo(mountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("read mountinfo: %w", err)
	}

	// Collect cgroup-v2 metadata for the differ's CgroupDelegationExposure
	// classifier. Same reasoning as mountinfo: best read from host /proc
	// before setns. Failure here is non-fatal — cgroup capture returns a
	// zero CgroupInfo and the walk still produces a useful ObservedSet.
	cgroup := readCgroupInfo(c.InitPID)

	// setns(CLONE_NEWNS) fails with EINVAL if the calling thread shares its
	// filesystem attributes (cwd, root, umask) with any other thread in the
	// process — which is the Go runtime's default. Detach this thread's fs
	// from the rest of the process first. CLONE_FS only affects this thread
	// because we are locked to it and will never return it to the runtime.
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return nil, fmt.Errorf("unshare(CLONE_FS): %w", err)
	}

	// Open every namespace handle BEFORE any setns: once we enter the mount
	// namespace, paths like /proc/<host-pid>/ns/... resolve in the container
	// and we can no longer reach the host's ns files.
	fds := make(map[string]int, len(nsToEnter))
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for _, ns := range nsToEnter {
		nsPath, ok := c.NSPaths[ns]
		if !ok || nsPath == "" {
			return nil, fmt.Errorf("container %q: missing %s namespace path", c.ID, ns)
		}
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("open %s (%s): %w", ns, nsPath, err)
		}
		fds[ns] = fd
	}
	for _, ns := range nsToEnter {
		if err := unix.Setns(fds[ns], 0); err != nil {
			return nil, fmt.Errorf("setns %s: %w", ns, err)
		}
	}

	entries := walk("/proc", mounts)
	for path, obs := range walk("/sys", mounts) {
		entries[path] = obs
	}

	return &ObservedSet{
		ContainerID: c.ID,
		InitPID:     c.InitPID,
		Cgroup:      cgroup,
		Entries:     entries,
		Mounts:      mounts,
	}, nil
}
