package spec

import (
	"testing"
)

func TestLoad_RuncDefault(t *testing.T) {
	set, err := Load("testdata/runc-default-config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Spot-check a masked path.
	if got, ok := set.Entries["/proc/kcore"]; !ok || got.Kind != KindMasked {
		t.Errorf("/proc/kcore: got %+v, want kind=%s", got, KindMasked)
	}
	// Spot-check a read-only path.
	if got, ok := set.Entries["/proc/sys"]; !ok || got.Kind != KindReadOnly {
		t.Errorf("/proc/sys: got %+v, want kind=%s", got, KindReadOnly)
	}
	// Spot-check a mount.
	got, ok := set.Entries["/sys/fs/cgroup"]
	if !ok || got.Kind != KindMounted {
		t.Fatalf("/sys/fs/cgroup: got %+v, want kind=%s", got, KindMounted)
	}
	if got.Type != "cgroup" || got.Source != "cgroup" {
		t.Errorf("/sys/fs/cgroup: type=%q source=%q, want type=cgroup source=cgroup", got.Type, got.Source)
	}
	wantOpt := "ro"
	found := false
	for _, o := range got.Options {
		if o == wantOpt {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("/sys/fs/cgroup: options=%v missing %q", got.Options, wantOpt)
	}

	// Namespaces: should have the standard six.
	if n := len(set.Namespaces); n != 6 {
		t.Errorf("namespaces: got %d, want 6 (%+v)", n, set.Namespaces)
	}
}

func TestFromSpec_Precedence(t *testing.T) {
	// If the same path appears as a mount AND in maskedPaths, the mount entry wins.
	raw := []byte(`{
		"mounts": [
			{ "destination": "/proc/kcore", "type": "bind", "source": "/dev/null", "options": ["bind", "ro"] }
		],
		"linux": {
			"maskedPaths": ["/proc/kcore"],
			"readonlyPaths": ["/proc/kcore"]
		}
	}`)
	set, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, ok := set.Entries["/proc/kcore"]
	if !ok {
		t.Fatalf("/proc/kcore missing")
	}
	if got.Kind != KindMounted {
		t.Errorf("kind=%s, want %s (mount should win over masked/readonly)", got.Kind, KindMounted)
	}
	if got.Source != "/dev/null" {
		t.Errorf("source=%q, want /dev/null", got.Source)
	}
}

func TestParse_Empty(t *testing.T) {
	set, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(set.Entries) != 0 {
		t.Errorf("entries=%d, want 0", len(set.Entries))
	}
	if len(set.Namespaces) != 0 {
		t.Errorf("namespaces=%d, want 0", len(set.Namespaces))
	}
}

func TestParse_Invalid(t *testing.T) {
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("Parse(garbage): want error, got nil")
	}
}

func TestLoad_Missing(t *testing.T) {
	if _, err := Load("testdata/does-not-exist.json"); err == nil {
		t.Fatal("Load(missing): want error, got nil")
	}
}
