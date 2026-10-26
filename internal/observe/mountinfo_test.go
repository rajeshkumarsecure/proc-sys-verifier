package observe

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sampleMountInfo = `21 27 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
22 27 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
23 27 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=4053912k,nr_inodes=1013478,mode=755
38 21 0:34 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
80 22 0:21 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
81 22 0:5 /null /proc/kcore ro,nosuid,relatime - devtmpfs devtmpfs rw,size=4053912k,nr_inodes=1013478,mode=755
`

func TestParseMountInfo(t *testing.T) {
	got, err := ParseMountInfo(strings.NewReader(sampleMountInfo))
	if err != nil {
		t.Fatalf("ParseMountInfo: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("len=%d, want 6", len(got))
	}

	// Spot-check the cgroup2 line: ro mount, with one optional tag.
	cg := got[3]
	if cg.MountID != 38 || cg.ParentID != 21 {
		t.Errorf("cgroup ids: %d/%d, want 38/21", cg.MountID, cg.ParentID)
	}
	if cg.MountPoint != "/sys/fs/cgroup" {
		t.Errorf("cgroup mountpoint=%q", cg.MountPoint)
	}
	if cg.FSType != "cgroup2" {
		t.Errorf("cgroup fstype=%q", cg.FSType)
	}
	if !cg.ReadOnly() {
		t.Errorf("cgroup should be ro: opts=%v", cg.VFSOptions)
	}
	if !reflect.DeepEqual(cg.Optional, []string{"shared:9"}) {
		t.Errorf("cgroup optional=%v, want [shared:9]", cg.Optional)
	}

	// The /proc line has no optional tag; ensure empty slice (not panic).
	pr := got[1]
	if pr.MountPoint != "/proc" || pr.ReadOnly() {
		t.Errorf("proc: mp=%q ro=%v", pr.MountPoint, pr.ReadOnly())
	}

	// /proc/kcore should be ro and bind-mounted from devtmpfs (the "masked" trick).
	kc := got[5]
	if kc.MountPoint != "/proc/kcore" || !kc.ReadOnly() {
		t.Errorf("kcore: mp=%q ro=%v", kc.MountPoint, kc.ReadOnly())
	}
}

func TestParseMountInfo_OctalEscapes(t *testing.T) {
	// Path with a space (\040) and a tab (\011).
	line := `42 30 0:1 /a\040b /mount\011point rw - tmpfs tmpfs rw`
	got, err := ParseMountInfo(strings.NewReader(line))
	if err != nil {
		t.Fatalf("ParseMountInfo: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Root != "/a b" {
		t.Errorf("root=%q, want %q", got[0].Root, "/a b")
	}
	if got[0].MountPoint != "/mount\tpoint" {
		t.Errorf("mountpoint=%q, want %q", got[0].MountPoint, "/mount\tpoint")
	}
}

func TestParseMountInfo_Malformed(t *testing.T) {
	cases := []string{
		"this has no separator at all",
		"1 2 0:5 / /x rw\n",      // no separator
		"1 2 not_dev / /x rw - tmpfs t rw", // bad dev field
		"1 2 0:bad / /x rw - tmpfs t rw",   // bad minor
		"1 2 0:5 / /x rw - tmpfs",          // too few post-separator fields
		"not_an_id 2 0:5 / /x rw - tmpfs t rw", // bad mount id
		"1 not_pid 0:5 / /x rw - tmpfs t rw",   // bad parent id
		"1 2 nodev / /x rw - tmpfs t rw",       // dev missing colon
		"a b c d e",                            // too few pre-separator fields
		"1 2 0:5 / /x rw - tmpfs t rw\n1 2 not_dev / /x rw - tmpfs t rw", // second line bad
	}
	for _, c := range cases {
		if _, err := ParseMountInfo(strings.NewReader(c)); err == nil {
			t.Errorf("ParseMountInfo(%q): want error, got nil", c)
		}
	}
}

func TestReadMountInfo_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(path, []byte(sampleMountInfo), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMountInfo(path)
	if err != nil {
		t.Fatalf("ReadMountInfo: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("len=%d, want 6", len(got))
	}
	if got[0].MountPoint != "/sys" {
		t.Errorf("got[0].MountPoint=%q, want /sys", got[0].MountPoint)
	}
}

func TestReadMountInfo_Missing(t *testing.T) {
	if _, err := ReadMountInfo("/no/such/file"); err == nil {
		t.Fatal("ReadMountInfo(missing): want error, got nil")
	}
}

func TestMountIndex_NoMatch(t *testing.T) {
	// No '/' mount means a path that doesn't share a prefix with any entry
	// gets no match.
	mounts := []MountInfo{
		{MountID: 5, MountPoint: "/proc"},
		{MountID: 6, MountPoint: "/sys"},
	}
	idx := indexMounts(mounts)
	if m := idx.containing("/etc/hostname"); m != nil {
		t.Errorf("containing returned %+v, want nil", m)
	}
	// Empty index returns nil for any path.
	emptyIdx := indexMounts(nil)
	if m := emptyIdx.containing("/proc/cpuinfo"); m != nil {
		t.Errorf("empty index returned %+v, want nil", m)
	}
}

func TestMountIndex_LongestPrefixWins(t *testing.T) {
	mounts := []MountInfo{
		{MountID: 1, MountPoint: "/"},
		{MountID: 2, MountPoint: "/proc"},
		{MountID: 3, MountPoint: "/proc/sys"},
		{MountID: 4, MountPoint: "/sys/fs/cgroup", VFSOptions: []string{"ro"}},
	}
	idx := indexMounts(mounts)

	cases := []struct {
		path string
		want int
	}{
		{"/etc/passwd", 1},
		{"/proc/cpuinfo", 2},
		{"/proc/sys/kernel/hostname", 3},
		{"/proc/sys", 3},
		{"/sys/fs/cgroup/cgroup.procs", 4},
		{"/sys/fs/cgroup", 4},
	}
	for _, c := range cases {
		m := idx.containing(c.path)
		if m == nil {
			t.Errorf("%s: no match", c.path)
			continue
		}
		if m.MountID != c.want {
			t.Errorf("%s: got mount id %d, want %d", c.path, m.MountID, c.want)
		}
	}
}
