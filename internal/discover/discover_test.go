package discover

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func fakeRunner(out []byte, err error) Runner {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return out, err
	}
}

func TestRuncSource_List_TwoContainers(t *testing.T) {
	raw := []byte(`[
		{
			"ociVersion": "1.0.2-dev",
			"id": "alpha",
			"pid": 1234,
			"status": "running",
			"bundle": "/run/runc/alpha",
			"rootfs": "/run/runc/alpha/rootfs",
			"created": "2026-01-01T00:00:00Z",
			"owner": "root"
		},
		{
			"ociVersion": "1.0.2-dev",
			"id": "beta",
			"pid": 5678,
			"status": "paused",
			"bundle": "/run/runc/beta",
			"rootfs": "/run/runc/beta/rootfs",
			"created": "2026-01-02T00:00:00Z",
			"owner": "root"
		}
	]`)

	s := &RuncSource{Binary: "/usr/bin/runc", Run: fakeRunner(raw, nil)}
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2 (%+v)", len(got), got)
	}

	want0 := Container{
		ID:         "alpha",
		Runtime:    "runc",
		Status:     "running",
		InitPID:    1234,
		BundlePath: "/run/runc/alpha",
		SpecPath:   "/run/runc/alpha/config.json",
		NSPaths:    nsPathsForPID(1234),
	}
	if !reflect.DeepEqual(got[0], want0) {
		t.Errorf("got[0]\n got = %+v\nwant = %+v", got[0], want0)
	}
	if got[1].ID != "beta" || got[1].Status != "paused" {
		t.Errorf("got[1] = %+v", got[1])
	}
}

func TestRuncSource_List_Empty(t *testing.T) {
	// runc prints `null` when no containers exist.
	s := &RuncSource{Binary: "runc", Run: fakeRunner([]byte("null"), nil)}
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List(null): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len=%d, want 0", len(got))
	}

	s2 := &RuncSource{Binary: "runc", Run: fakeRunner([]byte(""), nil)}
	got2, err := s2.List(context.Background())
	if err != nil {
		t.Fatalf("List(empty): %v", err)
	}
	if len(got2) != 0 {
		t.Errorf("len=%d, want 0", len(got2))
	}
}

func TestRuncSource_List_ExecError(t *testing.T) {
	s := &RuncSource{Binary: "runc", Run: fakeRunner(nil, errors.New("boom"))}
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("want error, got nil")
	}
}

func TestRuncSource_List_BadJSON(t *testing.T) {
	s := &RuncSource{Binary: "runc", Run: fakeRunner([]byte("not json"), nil)}
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("want parse error, got nil")
	}
}

func TestNSPathsForPID(t *testing.T) {
	got := nsPathsForPID(42)
	want := map[string]string{
		"mnt":    "/proc/42/ns/mnt",
		"pid":    "/proc/42/ns/pid",
		"net":    "/proc/42/ns/net",
		"ipc":    "/proc/42/ns/ipc",
		"uts":    "/proc/42/ns/uts",
		"user":   "/proc/42/ns/user",
		"cgroup": "/proc/42/ns/cgroup",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestRuncSource_Root_NameAndArgs verifies that Root, when set, surfaces
// in Name() and prepends --root to the runc invocation.
func TestRuncSource_Root_NameAndArgs(t *testing.T) {
	var got []string
	captureRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte("null"), nil
	}
	s := &RuncSource{Binary: "runc", Root: "/run/containerd/runc/default", Run: captureRunner}
	if _, err := s.List(context.Background()); err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"runc", "--root", "/run/containerd/runc/default", "list", "-f", "json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("invocation:\n got = %v\nwant = %v", got, want)
	}
	if s.Name() != "runc(/run/containerd/runc/default)" {
		t.Errorf("Name() = %q, want it to mention the root", s.Name())
	}
}

func TestRuncSource_NoRoot_OmitsRootFlag(t *testing.T) {
	var got []string
	captureRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte("null"), nil
	}
	s := &RuncSource{Binary: "runc", Run: captureRunner}
	if _, err := s.List(context.Background()); err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"runc", "list", "-f", "json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("invocation:\n got = %v\nwant = %v", got, want)
	}
	if s.Name() != "runc" {
		t.Errorf("Name() = %q, want plain 'runc'", s.Name())
	}
}

// TestRuncSource_Available_RootMustExist guards the contract that
// defaultSources() relies on: an alternate-root source self-disables when
// the directory is missing (e.g. hosts without containerd).
func TestRuncSource_Available_RootMustExist(t *testing.T) {
	s := &RuncSource{Binary: "/usr/bin/runc", Root: "/no/such/root/path/xyz"}
	if s.Available(context.Background()) {
		t.Error("Available() = true for nonexistent root; want false")
	}
}

// Stub source for All() tests.
type stubSource struct {
	name string
	ok   bool
	list []Container
	err  error
}

func (s *stubSource) Name() string                            { return s.name }
func (s *stubSource) Available(ctx context.Context) bool      { return s.ok }
func (s *stubSource) List(ctx context.Context) ([]Container, error) { return s.list, s.err }

func TestAll_DedupesAndSorts(t *testing.T) {
	sources := []Source{
		&stubSource{name: "a", ok: true, list: []Container{{ID: "z"}, {ID: "m"}}},
		&stubSource{name: "b", ok: true, list: []Container{{ID: "m"}, {ID: "a"}}}, // m duplicated
		&stubSource{name: "c", ok: false, list: []Container{{ID: "skipped"}}},
	}
	got, err := All(context.Background(), sources)
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3 (%+v)", len(got), got)
	}
	if got[0].ID != "a" || got[1].ID != "m" || got[2].ID != "z" {
		t.Errorf("order = [%s %s %s], want [a m z]", got[0].ID, got[1].ID, got[2].ID)
	}
}

func TestAll_PropagatesErrors(t *testing.T) {
	sources := []Source{
		&stubSource{name: "ok", ok: true, list: []Container{{ID: "x"}}},
		&stubSource{name: "broken", ok: true, err: errors.New("nope")},
	}
	got, err := All(context.Background(), sources)
	if err == nil {
		t.Fatal("want joined error, got nil")
	}
	if len(got) != 1 || got[0].ID != "x" {
		t.Errorf("partial result = %+v, want [{x}]", got)
	}
}

func TestAll_SkipsEmptyIDs(t *testing.T) {
	sources := []Source{
		&stubSource{name: "a", ok: true, list: []Container{{ID: ""}, {ID: "real"}}},
	}
	got, err := All(context.Background(), sources)
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(got) != 1 || got[0].ID != "real" {
		t.Errorf("got %+v, want [{real}]", got)
	}
}
