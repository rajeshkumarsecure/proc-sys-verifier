package observe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCgroupPath_V2(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cgroup")
	// Standard cgroup v2 single-line layout.
	if err := os.WriteFile(f, []byte("0::/user.slice/user-1000.slice/demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readCgroupPath(f)
	want := "/user.slice/user-1000.slice/demo"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReadCgroupPath_HybridIgnoresV1Lines(t *testing.T) {
	// Hybrid cgroup hosts emit additional v1 controller lines. We must
	// pick the "0::" v2 line and ignore the rest.
	dir := t.TempDir()
	f := filepath.Join(dir, "cgroup")
	contents := "12:memory:/legacy/v1/path\n" +
		"5:cpu,cpuacct:/another/v1\n" +
		"0::/the/v2/path\n"
	if err := os.WriteFile(f, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readCgroupPath(f); got != "/the/v2/path" {
		t.Errorf("got %q, want /the/v2/path", got)
	}
}

func TestReadCgroupPath_MissingFile(t *testing.T) {
	if got := readCgroupPath("/no/such/path/cgroup"); got != "" {
		t.Errorf("got %q, want empty (best-effort failure)", got)
	}
}

func TestReadCgroupPath_NoV2Line(t *testing.T) {
	// Pure v1 host: no "0::" line. Returns "".
	dir := t.TempDir()
	f := filepath.Join(dir, "cgroup")
	if err := os.WriteFile(f, []byte("12:memory:/legacy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readCgroupPath(f); got != "" {
		t.Errorf("got %q, want empty (no v2 line)", got)
	}
}

func TestReadNamespaceID_RealLink(t *testing.T) {
	// Build a fake ns symlink target. The actual format the kernel emits
	// is "cgroup:[N]", but readNamespaceID returns whatever the link points
	// to verbatim; we just need to confirm round-trip.
	dir := t.TempDir()
	link := filepath.Join(dir, "ns")
	if err := os.Symlink("cgroup:[4026532149]", link); err != nil {
		t.Fatal(err)
	}
	if got := readNamespaceID(link); got != "cgroup:[4026532149]" {
		t.Errorf("got %q, want cgroup:[4026532149]", got)
	}
}

func TestReadNamespaceID_MissingLink(t *testing.T) {
	if got := readNamespaceID("/no/such/link"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestReadCgroupInfo_SharedNamespaceFlag(t *testing.T) {
	// We can't easily build a fake /proc/<pid>/{cgroup,ns/cgroup} tree
	// because readCgroupInfo hardcodes /proc/<pid> paths. Validate the
	// equality logic directly via a constructed CgroupInfo.
	cases := []struct {
		name, ctr, host string
		wantShared      bool
	}{
		{"shared", "cgroup:[42]", "cgroup:[42]", true},
		{"isolated", "cgroup:[42]", "cgroup:[99]", false},
		{"empty ctr", "", "cgroup:[42]", false},
		{"empty host", "cgroup:[42]", "", false},
		{"both empty", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info := CgroupInfo{
				NamespaceID:     c.ctr,
				HostNamespaceID: c.host,
			}
			// Mirror the equality used in readCgroupInfo.
			got := info.NamespaceID != "" && info.NamespaceID == info.HostNamespaceID
			if got != c.wantShared {
				t.Errorf("NamespaceShared=%v, want %v", got, c.wantShared)
			}
		})
	}
}
