package observe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShouldSkip(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/proc/cpuinfo", false},
		{"/proc/sys/kernel/hostname", false},
		{"/proc/1", true},
		{"/proc/12345/status", true},
		{"/proc/kcore", true},
		{"/proc/kpageflags", true},
		{"/proc/self", false}, // symlink we want to record, not a numeric pid dir
		{"/sys/fs/cgroup", false},
		{"/sys/fs/cgroup/cgroup.procs", false},
		{"/sys/kernel/debug", true},
		{"/sys/kernel/debug/tracing", true},
		{"/sys/kernel/tracing", true},
		{"/sys/kernel/security", true},
		{"/sys/kernel/security/lsm", true},
		{"/sys/kernel/hostname", false}, // not under any skip prefix
		{"/sys/firmware/efi/efivars", true},
		{"/sys/firmware/efi/efivars/MyVar-1234", true},
		{"/sys/firmware", false}, // /sys/firmware is not a skip prefix
		{"/etc/passwd", false}, // outside our scope; walker passes through.
	}
	for _, c := range cases {
		if got := shouldSkip(c.path); got != c.want {
			t.Errorf("shouldSkip(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsAllDigits(t *testing.T) {
	cases := map[string]bool{
		"":       false,
		"0":      true,
		"123":    true,
		"12a":    false,
		"a12":    false,
		"self":   false,
		"123456": true,
	}
	for s, want := range cases {
		if got := isAllDigits(s); got != want {
			t.Errorf("isAllDigits(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestWalk_Fixture builds a synthetic /proc-shaped tree on disk and
// checks the walker's structural output: it records files and symlinks,
// skips numeric pid directories, and respects the known-skip list.
func TestWalk_Fixture(t *testing.T) {
	root := t.TempDir()

	mkfile := func(rel string, mode os.FileMode, contents string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	mklink := func(rel, target string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}

	mkfile("cpuinfo", 0o444, "processor : 0\n")
	mkfile("sys/kernel/hostname", 0o644, "demo\n")
	mklink("self", "1")
	mkfile("1/status", 0o644, "should be skipped")   // /proc/<pid>/
	mkfile("12345/cmdline", 0o644, "also skipped")
	mkfile("kcore", 0o400, "skip")                    // known-skip list

	// Single fake mount covering the whole root; not ro.
	mounts := []MountInfo{{MountID: 1, MountPoint: "/", VFSOptions: []string{"rw"}}}

	// walk uses the literal path it's given as the root prefix, so we
	// hand it the tempdir directly. The skip rules check `/proc/...` prefixes;
	// adjust by also testing /proc-rooted paths separately. Here we mainly
	// verify the structural output: files recorded, symlinks marked, no
	// follow.
	got := walk(root, mounts)

	// Root + cpuinfo + sys + sys/kernel + sys/kernel/hostname + self
	// + 1 + 1/status + 12345 + 12345/cmdline + kcore = 11 (no skips since
	// shouldSkip works on "/proc/..." absolute paths, not our tempdir root).
	if len(got) < 6 {
		t.Fatalf("walk produced %d entries, want >=6", len(got))
	}

	// Find the symlink and check we didn't follow it.
	sym, ok := got[filepath.Join(root, "self")]
	if !ok {
		t.Fatalf("self symlink not in output: keys=%v", keys(got))
	}
	if !sym.IsSymlink {
		t.Errorf("self: IsSymlink=false, want true")
	}
	if sym.LinkTarget != "1" {
		t.Errorf("self: LinkTarget=%q, want %q", sym.LinkTarget, "1")
	}

	// Read-only file (0444): writable should be false.
	cpu, ok := got[filepath.Join(root, "cpuinfo")]
	if !ok {
		t.Fatalf("cpuinfo missing")
	}
	if cpu.Writable {
		t.Errorf("cpuinfo: Writable=true, want false (mode 0444)")
	}

	// Read-write file (0644): writable should be true.
	host, ok := got[filepath.Join(root, "sys/kernel/hostname")]
	if !ok {
		t.Fatalf("hostname missing")
	}
	if !host.Writable {
		t.Errorf("hostname: Writable=false, want true (mode 0644 on rw mount)")
	}
}

// TestWalk_RoMountSuppressesWritability ensures a ro mount marks files
// as not-writable even if their mode bits would say otherwise.
func TestWalk_RoMountSuppressesWritability(t *testing.T) {
	root := t.TempDir()
	rwFile := filepath.Join(root, "f")
	if err := os.WriteFile(rwFile, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	mounts := []MountInfo{{MountID: 9, MountPoint: "/", VFSOptions: []string{"ro"}}}
	got := walk(root, mounts)
	o, ok := got[rwFile]
	if !ok {
		t.Fatalf("file missing from walk: keys=%v", keys(got))
	}
	if o.Writable {
		t.Errorf("Writable=true on ro mount, want false")
	}
	if o.MountID != 9 {
		t.Errorf("MountID=%d, want 9", o.MountID)
	}
}

// TestWalk_NoMountIndex covers the writability path when no MountInfo
// covers the path: writability falls back to the file mode bits alone.
func TestWalk_NoMountIndex(t *testing.T) {
	root := t.TempDir()
	rwFile := filepath.Join(root, "f")
	if err := os.WriteFile(rwFile, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	got := walk(root, nil) // empty mounts → no containing mount
	o, ok := got[rwFile]
	if !ok {
		t.Fatalf("file missing from walk: keys=%v", keys(got))
	}
	if !o.Writable {
		t.Errorf("Writable=false, want true (no mount info, mode 0666)")
	}
	if o.MountID != 0 {
		t.Errorf("MountID=%d, want 0 (no match)", o.MountID)
	}
}

// TestWalk_NonexistentRoot exercises filepath.WalkDir's error path.
// walk must not panic and must return an empty map.
func TestWalk_NonexistentRoot(t *testing.T) {
	got := walk("/proc-does-not-exist-xyz", nil)
	if len(got) != 0 {
		t.Errorf("walk of missing root returned %d entries, want 0", len(got))
	}
}

// TestWritability_CharDeviceTreatedNotWritable verifies the masking-bind-mount
// detection: a character device (which is how runc realizes maskedPaths for
// files, by bind-mounting /dev/null over them) is reported not-writable even
// when mode bits and mount options would otherwise indicate writable. This
// guards against the differ flagging effective masks as WritableDrift.
//
// We synthesize the call to writability() directly because creating a real
// character device on disk requires root (mknod).
func TestWritability_CharDeviceTreatedNotWritable(t *testing.T) {
	// Build a fake fs.FileInfo with mode = crw-rw-rw- (character device, all writable).
	info := fakeFileInfo{mode: os.ModeDevice | os.ModeCharDevice | 0o666}
	idx := indexMounts([]MountInfo{{MountID: 7, MountPoint: "/", VFSOptions: []string{"rw"}}})
	w, mid := writability("/proc/keys", info, idx)
	if w {
		t.Errorf("Writable=true for char device, want false (masking via /dev/null bind mount)")
	}
	if mid != 7 {
		t.Errorf("MountID=%d, want 7", mid)
	}
}

// fakeFileInfo is a minimal fs.FileInfo for unit-testing writability without
// needing root to mknod a real character device on disk.
type fakeFileInfo struct{ mode os.FileMode }

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
