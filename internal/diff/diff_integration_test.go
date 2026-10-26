//go:build integration

package diff

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/discover"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
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

func firstRuncContainer(t *testing.T) discover.Container {
	t.Helper()
	src := discover.NewRuncSource()
	cs, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("runc list: %v", err)
	}
	for _, c := range cs {
		if c.Status == "running" && c.InitPID > 0 && c.SpecPath != "" {
			return c
		}
	}
	t.Skip("integration: no running runc containers with a known spec path")
	return discover.Container{}
}

// TestIntegration_Scan_LiveRunc runs the full pipeline against a real
// container and asserts the baseline invariant: a runc-default container
// should have ZERO WritableDrift deviations. If this ever fails, either
// runc shipped a regression or our observer/differ disagree about what
// "writable" means — both are interesting.
func TestIntegration_Scan_LiveRunc(t *testing.T) {
	requireRoot(t)
	requireRunc(t)
	c := firstRuncContainer(t)
	t.Logf("scanning container %s (pid %d, spec %s)", c.ID, c.InitPID, c.SpecPath)

	intended, err := spec.Load(c.SpecPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	observed, err := observe.Container(ctx, c)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	res := Diff(intended, observed)
	if len(res.Deviations) != 0 {
		// Print everything so a regression is easy to diagnose.
		t.Errorf("expected 0 deviations on a runc-default container, got %d:", len(res.Deviations))
		for _, d := range res.Deviations {
			t.Errorf("  %s %s observed=%+v intended=%+v", d.Class, d.Path, d.Observed, d.Intended)
		}
	}
	// Annotations are info-level and may or may not appear depending on
	// whether the container has any writable delegated-leaf cgroup files
	// (the runc default mounts /sys/fs/cgroup ro, so usually none). Log
	// the count for visibility — non-fatal either way.
	t.Logf("annotations: %d", len(res.Annotations))
}
