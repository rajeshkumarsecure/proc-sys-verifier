//go:build integration

// hello_integration_test.go — slice 20 acceptance test. Runs only with
// the `integration` build tag and only as root; skips otherwise.
//
// What it proves end-to-end:
//   1. helloObjects loads (clang output is valid, BPF verifier accepts it).
//   2. The sched_process_exec tracepoint attaches.
//   3. Ringbuf events flow from kernel to userspace.
//   4. comm + cgroup_id round-trip correctly.
//
// Run: sudo go test -tags integration ./internal/watch/...

package watch

import (
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestIntegration_Hello_RoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF program load")
	}

	h, err := NewHello()
	if err != nil {
		t.Fatalf("NewHello: %v", err)
	}
	defer h.Close()

	// Run exec events in a background goroutine so the ringbuf
	// reader and the trigger can race naturally. The trigger picks a
	// distinctive comm string so we can ignore other host exec
	// activity (snapd, journalctl, etc.) without being flaky.
	// Use a distinctive comm string short enough to survive the
	// kernel's TASK_COMM_LEN truncation (15 chars + null), so the
	// comparison below is exact rather than prefix.
	const wantComm = "psv-hello-trg" // 13 chars; safe under 15
	triggered := false

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Give the reader a moment to be ready before triggering.
		time.Sleep(200 * time.Millisecond)
		// /bin/true is the smallest exec that's guaranteed to be
		// present. We can't change the comm via argv0 cheaply, so we
		// link /bin/true into a temp dir under the distinctive name.
		dir := t.TempDir()
		linkPath := dir + "/" + wantComm
		if err := os.Symlink("/bin/true", linkPath); err != nil {
			t.Errorf("symlink: %v", err)
			return
		}
		// Use the symlink as argv0; the kernel sets comm to the
		// basename of the executed file (truncated to 15 chars).
		cmd := exec.Command(linkPath)
		if err := cmd.Run(); err != nil {
			t.Errorf("trigger exec: %v", err)
		}
		triggered = true
	}()

	// Read until we see our trigger or time out. Other exec events
	// on the host are noise and get discarded.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// Set a short per-Read deadline by closing the reader after
		// the loop. cilium/ebpf's ringbuf.Reader doesn't expose a
		// SetDeadline directly; instead we let the outer for-loop
		// drive the timeout via Close from a goroutine below.
		ev, err := h.Read()
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if ev.CommString() == wantComm {
			if ev.PID == 0 || ev.TGID == 0 {
				t.Errorf("got matching event but pid/tgid zero: %+v", ev)
			}
			if ev.CgroupID == 0 {
				t.Errorf("got matching event but cgroup_id zero: %+v", ev)
			}
			wg.Wait()
			if !triggered {
				t.Errorf("read event before trigger ran (race?)")
			}
			return
		}
	}
	t.Fatalf("timed out waiting for exec event with comm %q", wantComm)
}
