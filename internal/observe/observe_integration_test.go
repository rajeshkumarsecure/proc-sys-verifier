//go:build integration

// Integration tests for the observer. These require:
//   - Linux host
//   - Root (real, not just CAP_SYS_ADMIN — needed for setns into another ns)
//   - A live runc container reachable via `runc list`
//
// Run with:
//
//	sudo -E $(which go) test -tags integration -run Integration ./internal/observe/...
//
// or via:
//
//	sudo -E make test-integration
//
// Tests skip loudly (t.Skip) when preconditions are missing so they never
// silently pass on a host that cannot actually exercise them.
package observe

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/discover"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration: requires root (re-run under sudo)")
	}
}

func requireRunc(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("runc"); err != nil {
		t.Skip("integration: requires runc on PATH")
	}
}

// firstRuncContainer returns the first running container reported by
// `runc list`, or skips the test if none exists.
func firstRuncContainer(t *testing.T) discover.Container {
	t.Helper()
	src := discover.NewRuncSource()
	cs, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("runc list: %v", err)
	}
	for _, c := range cs {
		if c.Status == "running" && c.InitPID > 0 {
			return c
		}
	}
	t.Skip("integration: no running runc containers; start one with `sudo runc run --detach <id>`")
	return discover.Container{}
}

// TestIntegration_Container_LiveRunc enters a real container's namespaces,
// walks its /proc, and asserts the basic invariants that prove setns worked
// and the in-namespace mountinfo was actually read from inside.
func TestIntegration_Container_LiveRunc(t *testing.T) {
	requireRoot(t)
	requireRunc(t)
	c := firstRuncContainer(t)
	t.Logf("observing container %s (pid %d)", c.ID, c.InitPID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	set, err := Container(ctx, c)
	if err != nil {
		t.Fatalf("Container: %v", err)
	}

	if set.ContainerID != c.ID {
		t.Errorf("ContainerID=%q, want %q", set.ContainerID, c.ID)
	}
	if set.InitPID != c.InitPID {
		t.Errorf("InitPID=%d, want %d", set.InitPID, c.InitPID)
	}
	if len(set.Entries) == 0 {
		t.Fatalf("no /proc entries observed")
	}
	if len(set.Mounts) == 0 {
		t.Fatalf("no mounts read from /proc/self/mountinfo")
	}

	// The container should have its own /proc mount. Confirm there is at
	// least one mountinfo line for /proc.
	var sawProcMount bool
	for _, m := range set.Mounts {
		if m.MountPoint == "/proc" && m.FSType == "proc" {
			sawProcMount = true
			break
		}
	}
	if !sawProcMount {
		t.Errorf("no proc mount on /proc in container mountinfo")
	}

	// runc's default spec marks /proc/sysrq-trigger as readonly (ro bind).
	// It should show up in mountinfo with the ro option, OR /proc/sys
	// should be read-only at the mount level.
	var sawROMaskOrBind bool
	for _, m := range set.Mounts {
		if !m.ReadOnly() {
			continue
		}
		switch m.MountPoint {
		case "/proc/sysrq-trigger", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys":
			sawROMaskOrBind = true
		}
		if strings.HasPrefix(m.MountPoint, "/proc/") {
			sawROMaskOrBind = true
		}
	}
	if !sawROMaskOrBind {
		t.Errorf("expected at least one ro bind mount under /proc; mounts=%+v", set.Mounts)
	}

	// Host mountinfo should report MORE entries than the container's view —
	// the container has a small, curated mount tree (~15-25 entries), the
	// host typically has 30+.
	//
	// We read PID 1's mountinfo, NOT /proc/self/mountinfo: the test process
	// runs Go's runtime, which may reuse the OS thread we locked for setns
	// before it has fully retired, so /proc/self/mountinfo can briefly
	// return the container's view. PID 1 is always in the host mount ns.
	host, err := ReadMountInfo("/proc/1/mountinfo")
	if err != nil {
		t.Fatalf("read host mountinfo: %v", err)
	}
	if len(set.Mounts) >= len(host) {
		t.Errorf("container has %d mounts, host has %d — container should have fewer (setns likely no-op)",
			len(set.Mounts), len(host))
	}

	// Container's root mount '/' should not match the host's root mount.
	// In the runc demo bundle the container's root is a bind mount over a
	// rootfs directory on disk, with a distinct source/root from the host.
	var hostRoot, ctrRoot *MountInfo
	for i := range host {
		if host[i].MountPoint == "/" {
			hostRoot = &host[i]
			break
		}
	}
	for i := range set.Mounts {
		if set.Mounts[i].MountPoint == "/" {
			ctrRoot = &set.Mounts[i]
			break
		}
	}
	if hostRoot != nil && ctrRoot != nil {
		if hostRoot.Source == ctrRoot.Source && hostRoot.Root == ctrRoot.Root {
			t.Errorf("container '/' (source=%q root=%q) matches host '/' (source=%q root=%q) — setns likely no-op",
				ctrRoot.Source, ctrRoot.Root, hostRoot.Source, hostRoot.Root)
		}
	}

	// Cgroup metadata should be populated for a runc-spawned container on
	// a cgroup-v2 host. Path starts with "/" (it's a cgroup path, not a
	// filesystem one); namespace IDs are kernel-formatted; and the demo
	// container has its own cgroup namespace, so NamespaceShared should be
	// false.
	if set.Cgroup.Path == "" {
		t.Errorf("Cgroup.Path is empty; expected a populated v2 path")
	} else if set.Cgroup.Path[0] != '/' {
		t.Errorf("Cgroup.Path=%q does not start with '/'", set.Cgroup.Path)
	}
	if set.Cgroup.NamespaceID == "" {
		t.Errorf("Cgroup.NamespaceID is empty")
	}
	if set.Cgroup.HostNamespaceID == "" {
		t.Errorf("Cgroup.HostNamespaceID is empty")
	}
	if set.Cgroup.NamespaceShared {
		t.Errorf("Cgroup.NamespaceShared=true on a runc-default container; expected its own cgroup ns")
	}
}
