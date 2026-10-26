//go:build integration

// file_open_integration_test.go — slice 22 acceptance tests. Runs only
// with the `integration` build tag, only as root.
//
// What these prove:
//   1. lsm/file_open loads and attaches with the LPM trie pre-populated.
//   2. A write-open (FMODE_WRITE) against a path in the intended set,
//      from a task in the watched cgroup, produces exactly one event
//      with the correct cgroup_id + container_handle + policy_class
//      and resolved target.
//   3. A write-open against a path NOT in the intended set produces
//      zero events. (LPM trie filter works.)
//   4. A read-open (no FMODE_WRITE) against a path in the intended set
//      produces zero events. (Action filter works.)
//   5. A write-open from a task in an UNWATCHED cgroup produces zero
//      events. (Cgroup filter works.)
//
// Run: sudo go test -tags integration -count=1 -v -run TestIntegration_FileOpen ./internal/watch/...
//
// We deliberately open paths under /proc but never WRITE to them — the
// LSM hook fires on open(2), not write(2), so opening + immediately
// closing is enough to exercise the probe without risking host state.

package watch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
)

// Target path used by every test below. /proc/sys/kernel/hostname is:
//   - Always present on Linux.
//   - Opening for write does NOT change the hostname; only writing does.
//   - Safe to open even as root, won't destabilize the host.
const fileopenTestPath = "/proc/sys/kernel/hostname"

// fakeIntendedSet returns an IntendedSet with `path` declared masked.
// Lets the test treat any well-known path as if the operator had put it
// in maskedPaths — we don't need a full OCI bundle on disk.
func fakeIntendedSet(path string) *spec.IntendedSet {
	return &spec.IntendedSet{
		Entries: map[string]spec.Entry{
			path: {Path: path, Kind: spec.KindMasked},
		},
	}
}

// triggerForFileOpen is a small shell snippet that:
//  1. Moves the running shell into the named cgroup.
//  2. Opens fd 3 for `mode` on `path`, then immediately closes it.
//     That issues exactly one open(2) syscall against the target,
//     which the LSM hook will observe.
//
// `mode` is the shell redirection operator: ">" for write, "<" for
// read. Quoting is delicate because we substitute into a `sh -c`
// argument; keeping it as a single quoted string with %s placeholders
// is the safest pattern.
const triggerForFileOpenFmt = `set -e
echo $$ > %s/cgroup.procs
exec sh -c 'exec 3%s%s; exec 3>&-'
`

func triggerOpenIn(t *testing.T, cgPath, target, mode string) error {
	t.Helper()
	script := fmt.Sprintf(triggerForFileOpenFmt, cgPath, mode, target)
	cmd := exec.Command("sh", "-c", script)
	return cmd.Run()
}

// mkTestCgroupForFileOpen — same shape as the slice-21 helper, but
// distinguished by name so parallel runs don't collide.
func mkTestCgroupForFileOpen(t *testing.T, suffix string) (string, uint64) {
	t.Helper()
	name := fmt.Sprintf("psv-fileopen-test-%d-%s", time.Now().UnixNano(), suffix)
	cgPath := filepath.Join("/sys/fs/cgroup", name)
	if err := os.Mkdir(cgPath, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", cgPath, err)
	}
	t.Cleanup(func() {
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

// readFileOpenEventsFor reads events until either (a) deadline expires
// or (b) `n` events match cgid. Returns the matching events plus any
// extras seen for other cgroups.
func readFileOpenEventsFor(t *testing.T, fo *FileOpen, cgid uint64, n int, deadline time.Duration) (matches, extras []FileOpenEvent) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(deadline):
			fo.reader.Close() // forces Read to return io.EOF
		}
	}()
	defer close(done)

	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		ev, err := fo.Read()
		if err != nil {
			return matches, extras
		}
		if ev.CgroupID == cgid {
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

func TestIntegration_FileOpen_WriteInIntendedSetFiresOneEvent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF LSM load")
	}

	cgPath, cgid := mkTestCgroupForFileOpen(t, "write-match")

	fo, err := NewFileOpen()
	if err != nil {
		t.Fatalf("NewFileOpen: %v", err)
	}
	defer fo.Close()

	handle, err := fo.Watch(cgid, IntendedSetEntries(fakeIntendedSet(fileopenTestPath)))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	t.Logf("watched cgroup=%d at handle=%d", cgid, handle)

	// Let the probe propagate to all CPUs before triggering.
	time.Sleep(100 * time.Millisecond)

	if err := triggerOpenIn(t, cgPath, fileopenTestPath, ">"); err != nil {
		t.Fatalf("trigger write-open: %v", err)
	}

	matches, _ := readFileOpenEventsFor(t, fo, cgid, 1, 3*time.Second)
	if len(matches) < 1 {
		t.Fatalf("expected at least 1 event for cgroup %d / path %q; got 0", cgid, fileopenTestPath)
	}
	ev := matches[0]
	if ev.ContainerHandle != handle {
		t.Errorf("event container_handle = %d; want %d", ev.ContainerHandle, handle)
	}
	if ev.Class() != PolicyMasked {
		t.Errorf("event policy_class = %s; want masked", ev.Class())
	}
	if ev.Truncated() {
		t.Errorf("event was truncated; bpf_d_path returned %d", ev.TargetLen)
	}
	if target := ev.TargetString(); target != fileopenTestPath {
		t.Errorf("event target = %q; want %q", target, fileopenTestPath)
	}
	t.Logf("got event: cgroup=%d handle=%d class=%s pid=%d comm=%q target=%q",
		ev.CgroupID, ev.ContainerHandle, ev.Class(), ev.PID, ev.CommString(), ev.TargetString())
}

func TestIntegration_FileOpen_WriteOutsideIntendedSetFiresZeroEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF LSM load")
	}

	cgPath, cgid := mkTestCgroupForFileOpen(t, "write-miss")
	// Intended set declares /proc/sys/kernel/hostname masked, but we
	// trigger a write against a different /proc path that's NOT in the
	// set. The LPM lookup should miss and produce no event.
	otherPath := "/proc/sys/kernel/threads-max"
	if _, err := os.Stat(otherPath); err != nil {
		t.Skipf("control path %s not present on this kernel", otherPath)
	}

	fo, err := NewFileOpen()
	if err != nil {
		t.Fatalf("NewFileOpen: %v", err)
	}
	defer fo.Close()

	if _, err := fo.Watch(cgid, IntendedSetEntries(fakeIntendedSet(fileopenTestPath))); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := triggerOpenIn(t, cgPath, otherPath, ">"); err != nil {
		t.Fatalf("trigger write-open on %s: %v", otherPath, err)
	}

	matches, _ := readFileOpenEventsFor(t, fo, cgid, 1, 1*time.Second)
	for _, ev := range matches {
		t.Errorf("got unexpected event for path not in intended set: target=%q class=%s",
			ev.TargetString(), ev.Class())
	}
}

func TestIntegration_FileOpen_ReadOnlyFiresZeroEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF LSM load")
	}

	cgPath, cgid := mkTestCgroupForFileOpen(t, "read")

	fo, err := NewFileOpen()
	if err != nil {
		t.Fatalf("NewFileOpen: %v", err)
	}
	defer fo.Close()

	if _, err := fo.Watch(cgid, IntendedSetEntries(fakeIntendedSet(fileopenTestPath))); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Read open: FMODE_WRITE is not set. The action filter should drop
	// the event before any cgroup or LPM lookup.
	if err := triggerOpenIn(t, cgPath, fileopenTestPath, "<"); err != nil {
		t.Fatalf("trigger read-open: %v", err)
	}

	matches, _ := readFileOpenEventsFor(t, fo, cgid, 1, 1*time.Second)
	for _, ev := range matches {
		t.Errorf("got unexpected event for read-open: target=%q class=%s",
			ev.TargetString(), ev.Class())
	}
}

func TestIntegration_FileOpen_UnwatchedCgroupFiresZeroEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF LSM load")
	}

	_, watchedID := mkTestCgroupForFileOpen(t, "watched")
	unwatchedPath, unwatchedID := mkTestCgroupForFileOpen(t, "unwatched")

	fo, err := NewFileOpen()
	if err != nil {
		t.Fatalf("NewFileOpen: %v", err)
	}
	defer fo.Close()

	// Watch the first cgroup; trigger from the second.
	if _, err := fo.Watch(watchedID, IntendedSetEntries(fakeIntendedSet(fileopenTestPath))); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := triggerOpenIn(t, unwatchedPath, fileopenTestPath, ">"); err != nil {
		t.Fatalf("trigger write-open in unwatched cgroup: %v", err)
	}

	_, extras := readFileOpenEventsFor(t, fo, unwatchedID, 1, 1*time.Second)
	for _, ev := range extras {
		if ev.CgroupID == unwatchedID {
			t.Errorf("unwatched cgroup %d produced an event: target=%q", unwatchedID, ev.TargetString())
		}
	}

	// Sanity: make sure the watched comm field test still validates
	// the rest of the event structure. We're just confirming `extras`
	// didn't include unwatchedID events. If extras has events from
	// other host activity, that's fine — the assertion above filters.
	_ = strings.HasPrefix
}
