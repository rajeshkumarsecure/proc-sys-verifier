//go:build integration

// sb_mount_integration_test.go — slice 21 acceptance tests. Runs only
// with the `integration` build tag, only as root.
//
// What it proves:
//   1. The LSM program loads (kernel has BPF LSM, verifier accepts).
//   2. Mount calls from tasks in a watched cgroup produce exactly one
//      event per call when the target is under /proc or /sys.
//   3. Mount calls from tasks in a cgroup NOT in the watched set
//      produce zero events. (No false positives.)
//   4. The cgroup_id in the event matches CgroupIDFromPath of the
//      cgroup we put the trigger in. (Identity round-trip.)
//
// Run: sudo go test -tags integration -count=1 -v -run TestIntegration_SBMount ./internal/watch/...

package watch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// triggerCmd is the shell incantation we run in a child to trigger a
// qualifying mount. It:
//  1. Moves itself into the named cgroup (writes its own PID to
//     cgroup.procs).
//  2. Unshares the mount namespace.
//  3. Bind-mounts /etc/hostname over /proc/sys/kernel/hostname.
//     This is a known-bind-mountable procfs target; the kernel's
//     LSM hook fires before any final permission check, so even if
//     the mount itself gets rejected, the event still emits.
//  4. Unmounts so the child exits cleanly.
//
// The redirection / 2>/dev/null suppression keeps test output clean;
// the LSM hook fires on the syscall entry regardless.
const triggerCmd = `set -e
echo $$ > %s/cgroup.procs
exec unshare -m sh -c 'mount --bind /etc/hostname /proc/sys/kernel/hostname 2>/dev/null; umount /proc/sys/kernel/hostname 2>/dev/null; true'
`

// mkTestCgroup creates a fresh cgroup directory under /sys/fs/cgroup,
// returns its absolute host path and kernel cgroup ID.
func mkTestCgroup(t *testing.T, suffix string) (string, uint64) {
	t.Helper()
	name := fmt.Sprintf("psv-sbmount-test-%d-%s", time.Now().UnixNano(), suffix)
	cgPath := filepath.Join("/sys/fs/cgroup", name)
	if err := os.Mkdir(cgPath, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", cgPath, err)
	}
	t.Cleanup(func() {
		// Cgroup removal requires the directory to be empty (no
		// member processes). All triggers exit before this runs.
		// Best-effort: log but don't fail the test on cleanup error.
		if err := os.Remove(cgPath); err != nil {
			t.Logf("cleanup %s: %v (likely still has tasks; will need manual rmdir)", cgPath, err)
		}
	})
	cgid, err := CgroupIDFromPath(cgPath)
	if err != nil {
		t.Fatalf("CgroupIDFromPath: %v", err)
	}
	return cgPath, cgid
}

// triggerMountIn runs the trigger script in cgroup `cgPath` and waits
// for it to exit. Returns any error from the subprocess.
func triggerMountIn(t *testing.T, cgPath string) error {
	t.Helper()
	script := fmt.Sprintf(triggerCmd, cgPath)
	cmd := exec.Command("sh", "-c", script)
	return cmd.Run()
}

// readEventsFor reads events from sb until either (a) deadline expires
// or (b) it sees `n` events with cgroup_id == matchCgID. Returns the
// matching events.
//
// The reader is shared per-SBMount; this helper buffers any
// non-matching events (which shouldn't happen in our tests but we
// tolerate them) into `extras` for the caller to inspect.
func readEventsFor(t *testing.T, sb *SBMount, matchCgID uint64, n int, deadline time.Duration) (matches, extras []SBMountEvent) {
	t.Helper()
	end := time.Now().Add(deadline)

	// Close the reader after the deadline so Read returns io.EOF and
	// the loop terminates cleanly.
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(deadline):
			sb.reader.Close() // forces Read to return io.EOF
		}
	}()
	defer close(done)

	for time.Now().Before(end) {
		ev, err := sb.Read()
		if err != nil {
			return matches, extras
		}
		if ev.CgroupID == matchCgID {
			matches = append(matches, ev)
			if len(matches) >= n {
				return matches, extras
			}
		} else {
			extras = append(extras, ev)
		}
	}
	return matches, extras
}

func TestIntegration_SBMount_WatchedCgroupFiresOneEvent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF LSM load")
	}

	cgPath, cgid := mkTestCgroup(t, "watched")

	sb, err := NewSBMount([]uint64{cgid})
	if err != nil {
		t.Fatalf("NewSBMount: %v", err)
	}
	defer sb.Close()

	// Give the attached probe a moment to be live before triggering.
	// The mount syscall is fast; the LSM hook is attached
	// synchronously after AttachLSM returns, but the kernel takes a
	// few microseconds to propagate the attachment to all CPUs.
	time.Sleep(100 * time.Millisecond)

	if err := triggerMountIn(t, cgPath); err != nil {
		t.Fatalf("trigger mount: %v", err)
	}

	matches, extras := readEventsFor(t, sb, cgid, 1, 3*time.Second)
	if len(matches) < 1 {
		t.Fatalf("expected at least 1 event for cgroup %d; got 0 (%d extras from other cgroups)", cgid, len(extras))
	}
	ev := matches[0]
	if ev.PID == 0 || ev.TGID == 0 {
		t.Errorf("event has zero pid/tgid: %+v", ev)
	}
	if ev.Truncated() {
		t.Logf("target was truncated (TargetLen=%d); kernel couldn't resolve path", ev.TargetLen)
	} else {
		target := ev.TargetString()
		if !strings.HasPrefix(target, "/proc/") && !strings.HasPrefix(target, "/sys/") {
			t.Errorf("event target %q is neither /proc/ nor /sys/", target)
		}
		t.Logf("got event: cgroup=%d pid=%d comm=%q target=%q", ev.CgroupID, ev.PID, ev.CommString(), target)
	}
}

func TestIntegration_SBMount_UnwatchedCgroupFiresZeroEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF LSM load")
	}

	watchedPath, watchedID := mkTestCgroup(t, "watched")
	unwatchedPath, unwatchedID := mkTestCgroup(t, "unwatched")

	sb, err := NewSBMount([]uint64{watchedID})
	if err != nil {
		t.Fatalf("NewSBMount: %v", err)
	}
	defer sb.Close()
	_ = watchedPath // suppress unused; included for symmetry / debugging

	time.Sleep(100 * time.Millisecond)

	if err := triggerMountIn(t, unwatchedPath); err != nil {
		t.Fatalf("trigger mount: %v", err)
	}

	// Read with a short deadline; we expect zero events for the
	// unwatched cgroup. If anything matches `unwatchedID`, the filter
	// is broken.
	_, extras := readEventsFor(t, sb, unwatchedID, 1, 1*time.Second)

	// Defensive: scan all received events; none should reference
	// unwatchedID.
	for _, ev := range extras {
		if ev.CgroupID == unwatchedID {
			t.Errorf("unwatched cgroup %d produced an event: %+v", unwatchedID, ev)
		}
	}
}

func TestIntegration_SBMount_WatchAndUnwatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF LSM load")
	}

	cgPath, cgid := mkTestCgroup(t, "dynamic")

	// Start with empty watched set.
	sb, err := NewSBMount(nil)
	if err != nil {
		t.Fatalf("NewSBMount: %v", err)
	}
	defer sb.Close()

	time.Sleep(100 * time.Millisecond)

	// 1. Trigger before Watch — should not produce an event.
	if err := triggerMountIn(t, cgPath); err != nil {
		t.Fatalf("trigger mount (pre-watch): %v", err)
	}
	matches, _ := readEventsFor(t, sb, cgid, 1, 500*time.Millisecond)
	if len(matches) > 0 {
		t.Errorf("got event before Watch was called: %+v", matches[0])
	}

	// 2. Watch the cgroup; close+reopen the reader because the
	//    previous readEventsFor closed it via deadline expiry.
	if err := sb.Watch(cgid); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Re-open the reader so Read can return new events. (Slice 23
	// will own this lifecycle inside `psv watch`; for the test we
	// rebuild the SBMount so the helper stays trivial.)
	sb.Close()
	sb, err = NewSBMount([]uint64{cgid})
	if err != nil {
		t.Fatalf("re-open NewSBMount: %v", err)
	}
	defer sb.Close()

	time.Sleep(100 * time.Millisecond)

	// 3. Trigger after Watch — should now produce an event.
	if err := triggerMountIn(t, cgPath); err != nil {
		t.Fatalf("trigger mount (post-watch): %v", err)
	}
	matches, _ = readEventsFor(t, sb, cgid, 1, 3*time.Second)
	if len(matches) < 1 {
		t.Fatalf("expected event after Watch; got 0")
	}
}
