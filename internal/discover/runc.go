package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// runcStateEntry mirrors the JSON shape emitted by `runc list -f json`. See
// https://github.com/opencontainers/runc/blob/main/list.go.
type runcStateEntry struct {
	OCIVersion     string            `json:"ociVersion"`
	ID             string            `json:"id"`
	InitProcessPid int               `json:"pid"`
	Status         string            `json:"status"`
	Bundle         string            `json:"bundle"`
	Rootfs         string            `json:"rootfs"`
	Created        string            `json:"created"`
	Annotations    map[string]string `json:"annotations,omitempty"`
	Owner          string            `json:"owner"`
}

// Runner abstracts command execution so tests can inject a fake `runc`.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// RuncSource lists containers via the runc CLI (`runc list -f json`).
//
// This is the smallest viable Source: no daemon, no socket, no vendored
// client. By default it lists containers in runc's own state directory
// (typically /run/runc/). To list containers created by another runtime
// that uses runc as a shim — most notably containerd, which stores its
// runc state under /run/containerd/runc/<containerd-namespace>/ — set
// Root to that directory. The verifier's defaultSources() probes the
// known containerd path automatically.
type RuncSource struct {
	// Binary is the runc executable. Default: "runc" (resolved via PATH).
	Binary string
	// Root is the runc state directory. Empty == runc's compiled-in
	// default (`/run/runc/`). Set to scan a containerd-managed root.
	Root string
	// Run is the command runner. Default: os/exec. Override in tests.
	Run Runner
}

// NewRuncSource returns a RuncSource using PATH-resolved `runc` and the
// default root. Use the zero value or set fields explicitly for more
// control (e.g. `&RuncSource{Root: "/run/containerd/runc/default"}`).
func NewRuncSource() *RuncSource { return &RuncSource{} }

func (s *RuncSource) binary() string {
	if s.Binary != "" {
		return s.Binary
	}
	return "runc"
}

func (s *RuncSource) runner() Runner {
	if s.Run != nil {
		return s.Run
	}
	return execRunner
}

// Name implements Source.
func (s *RuncSource) Name() string {
	if s.Root != "" {
		return "runc(" + s.Root + ")"
	}
	return "runc"
}

// Available implements Source: true iff the runc binary is resolvable
// AND (when Root is set) that root directory exists. The directory check
// lets defaultSources() unconditionally add a containerd-root source
// without it firing on hosts that don't run containerd.
func (s *RuncSource) Available(ctx context.Context) bool {
	if s.Binary == "" {
		if _, err := exec.LookPath("runc"); err != nil {
			return false
		}
	}
	if s.Root != "" {
		if st, err := os.Stat(s.Root); err != nil || !st.IsDir() {
			return false
		}
	}
	return true
}

// List implements Source. Calls `runc [--root <Root>] list -f json` and
// projects the result.
func (s *RuncSource) List(ctx context.Context) ([]Container, error) {
	args := make([]string, 0, 4)
	if s.Root != "" {
		args = append(args, "--root", s.Root)
	}
	args = append(args, "list", "-f", "json")
	out, err := s.runner()(ctx, s.binary(), args...)
	if err != nil {
		return nil, fmt.Errorf("exec runc list: %w", err)
	}
	return parseRuncList(out)
}

func parseRuncList(data []byte) ([]Container, error) {
	// runc emits `null` (not `[]`) when there are no containers.
	if len(data) == 0 {
		return nil, nil
	}
	var entries []runcStateEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse runc list: %w", err)
	}
	out := make([]Container, 0, len(entries))
	for _, e := range entries {
		out = append(out, runcEntryToContainer(e))
	}
	return out, nil
}

func runcEntryToContainer(e runcStateEntry) Container {
	c := Container{
		ID:         e.ID,
		Runtime:    "runc",
		Status:     e.Status,
		InitPID:    e.InitProcessPid,
		BundlePath: e.Bundle,
	}
	if e.Bundle != "" {
		c.SpecPath = filepath.Join(e.Bundle, "config.json")
	}
	if e.InitProcessPid > 0 {
		c.NSPaths = nsPathsForPID(e.InitProcessPid)
	}
	return c
}

// nsPathsForPID returns the standard set of namespace handle paths under
// /proc/<pid>/ns. We populate the slot regardless of whether the namespace is
// shared with the host — the observer decides whether to enter it.
func nsPathsForPID(pid int) map[string]string {
	base := fmt.Sprintf("/proc/%d/ns", pid)
	return map[string]string{
		"mnt":    filepath.Join(base, "mnt"),
		"pid":    filepath.Join(base, "pid"),
		"net":    filepath.Join(base, "net"),
		"ipc":    filepath.Join(base, "ipc"),
		"uts":    filepath.Join(base, "uts"),
		"user":   filepath.Join(base, "user"),
		"cgroup": filepath.Join(base, "cgroup"),
	}
}
