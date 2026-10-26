package diff

import (
	"strings"
	"testing"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
)

// observedSetWithCgroup is a fixture builder for tests that exercise the
// CgroupDelegationExposure classifier: it bundles entries, mounts, and
// CgroupInfo into a single ObservedSet.
func observedSetWithCgroup(cg observe.CgroupInfo, mounts []observe.MountInfo, entries ...observe.Observed) *observe.ObservedSet {
	m := map[string]observe.Observed{}
	for _, e := range entries {
		m[e.Path] = e
	}
	return &observe.ObservedSet{
		Cgroup:  cg,
		Mounts:  mounts,
		Entries: m,
	}
}

func TestIsInside(t *testing.T) {
	cases := []struct {
		child, parent string
		want          bool
	}{
		{"/a/b", "/a", true},
		{"/a", "/a", true},
		{"/a/b", "/a/b/c", false},
		{"/", "/", true},
		{"/a/b", "/", true}, // root is ancestor of all
		{"/ab", "/a", false}, // string prefix would lie; isInside requires /
		{"/a", "/b", false},
	}
	for _, c := range cases {
		if got := isInside(c.child, c.parent); got != c.want {
			t.Errorf("isInside(%q, %q) = %v, want %v", c.child, c.parent, got, c.want)
		}
	}
}

// Today's runc-default: container has its own cgroup ns, /sys/fs/cgroup is
// bind-mounted with root == container's cgroup, mount is ro. Any writable
// cgroup file lives inside the delegated subtree.
//
// Expected: no deviation. Annotation if any file is writable.
func TestCgroupDelegation_RuncDefault_NoDeviation(t *testing.T) {
	cg := observe.CgroupInfo{
		Path:            "/user.slice/user-1000.slice/demo",
		NamespaceID:     "cgroup:[42]",
		HostNamespaceID: "cgroup:[1]",
		NamespaceShared: false,
	}
	mounts := []observe.MountInfo{
		{
			MountID:    2632,
			MountPoint: "/sys/fs/cgroup",
			Root:       "/user.slice/user-1000.slice/demo",
			VFSOptions: []string{"ro", "nosuid", "nodev"},
			FSType:     "cgroup2",
		},
	}
	// Even simulate a writable knob (it's not in reality because the ro
	// mount suppresses writability, but we set it manually here to ensure
	// the classifier produces an annotation, not a deviation, for the
	// delegated-leaf case).
	obs := observedSetWithCgroup(cg, mounts, observe.Observed{
		Path: "/sys/fs/cgroup/cgroup.procs", Writable: true,
	})
	devs, anns := cgroupDelegation(obs)
	if len(devs) != 0 {
		t.Errorf("got %d deviations, want 0 (delegated-leaf): %+v", len(devs), devs)
	}
	if len(anns) != 1 {
		t.Fatalf("got %d annotations, want 1: %+v", len(anns), anns)
	}
	if anns[0].Kind != AnnotationDelegatedLeaf {
		t.Errorf("annotation kind = %q, want %q", anns[0].Kind, AnnotationDelegatedLeaf)
	}
	if anns[0].Path != "/sys/fs/cgroup/cgroup.procs" {
		t.Errorf("annotation path = %q", anns[0].Path)
	}
}

// systemd-in-container "sloppy": mount root is "/" (host root cgroup
// bind-mounted in), not the delegated subtree. A write to subtree_control
// at the in-container path /sys/fs/cgroup/cgroup.subtree_control lands at
// the host's /cgroup.subtree_control — outside the container's delegated
// subtree.
//
// Expected: CgroupDelegationExposure deviation, no annotation.
func TestCgroupDelegation_SloppyHostBind_FlagsExposure(t *testing.T) {
	cg := observe.CgroupInfo{
		Path:            "/user.slice/user-1000.slice/sloppy",
		NamespaceID:     "cgroup:[1]",
		HostNamespaceID: "cgroup:[1]",
		NamespaceShared: true, // --cgroupns=host scenario
	}
	mounts := []observe.MountInfo{
		{
			MountID:    100,
			MountPoint: "/sys/fs/cgroup",
			Root:       "/", // host root cgroup mounted in
			VFSOptions: []string{"rw", "nosuid"},
			FSType:     "cgroup2",
		},
	}
	obs := observedSetWithCgroup(cg, mounts, observe.Observed{
		Path: "/sys/fs/cgroup/cgroup.subtree_control", Writable: true,
	})
	devs, anns := cgroupDelegation(obs)
	if len(devs) != 1 {
		t.Fatalf("got %d deviations, want 1: %+v", len(devs), devs)
	}
	if len(anns) != 0 {
		t.Errorf("got %d annotations, want 0: %+v", len(anns), anns)
	}
	d := devs[0]
	if d.Class != ClassCgroupDelegationExposure {
		t.Errorf("class = %q, want %q", d.Class, ClassCgroupDelegationExposure)
	}
	obsPayload, ok := d.Observed.(CgroupDelegationExposureObserved)
	if !ok {
		t.Fatalf("Observed payload wrong type: %T", d.Observed)
	}
	if obsPayload.EffectivePath != "/cgroup.subtree_control" {
		t.Errorf("EffectivePath=%q, want /cgroup.subtree_control", obsPayload.EffectivePath)
	}
	if !obsPayload.MountRW {
		t.Errorf("MountRW=false, want true")
	}
	if !obsPayload.CgroupNSShared {
		t.Errorf("CgroupNSShared=false, want true")
	}
	if !strings.Contains(obsPayload.Effect, "shares host cgroup namespace") {
		t.Errorf("Effect should mention namespace sharing: %q", obsPayload.Effect)
	}
	intd, ok := d.Intended.(CgroupDelegationExposureIntended)
	if !ok || intd.DelegatedSubtree != cg.Path {
		t.Errorf("Intended payload = %+v, want DelegatedSubtree=%q", d.Intended, cg.Path)
	}
}

// systemd-in-container "proper": private cgroup ns, mount root IS the
// delegated subtree, mount is rw (systemd needs that to manage units).
// Writable files inside the subtree are delegated-leaf, not exposure.
func TestCgroupDelegation_ProperDelegation_AnnotationOnly(t *testing.T) {
	cg := observe.CgroupInfo{
		Path:            "/user.slice/user-1000.slice/proper",
		NamespaceID:     "cgroup:[99]",
		HostNamespaceID: "cgroup:[1]",
		NamespaceShared: false,
	}
	mounts := []observe.MountInfo{
		{
			MountID:    200,
			MountPoint: "/sys/fs/cgroup",
			Root:       "/user.slice/user-1000.slice/proper",
			VFSOptions: []string{"rw", "nosuid"},
			FSType:     "cgroup2",
		},
	}
	obs := observedSetWithCgroup(cg, mounts,
		observe.Observed{Path: "/sys/fs/cgroup/cgroup.procs", Writable: true},
		observe.Observed{Path: "/sys/fs/cgroup/cgroup.subtree_control", Writable: true},
	)
	devs, anns := cgroupDelegation(obs)
	if len(devs) != 0 {
		t.Errorf("got %d deviations, want 0: %+v", len(devs), devs)
	}
	if len(anns) != 2 {
		t.Errorf("got %d annotations, want 2: %+v", len(anns), anns)
	}
}

func TestCgroupDelegation_NotWritable_Skipped(t *testing.T) {
	cg := observe.CgroupInfo{Path: "/x"}
	mounts := []observe.MountInfo{{MountPoint: "/sys/fs/cgroup", Root: "/"}}
	obs := observedSetWithCgroup(cg, mounts, observe.Observed{
		Path: "/sys/fs/cgroup/cgroup.procs", Writable: false,
	})
	devs, anns := cgroupDelegation(obs)
	if len(devs) != 0 || len(anns) != 0 {
		t.Errorf("non-writable entries should produce nothing; got devs=%d anns=%d", len(devs), len(anns))
	}
}

func TestCgroupDelegation_NoCgroupPath_NoOp(t *testing.T) {
	// Cgroup capture failed (best-effort) — classifier returns nothing
	// rather than producing nonsense.
	obs := observedSetWithCgroup(
		observe.CgroupInfo{}, // empty Path
		[]observe.MountInfo{{MountPoint: "/sys/fs/cgroup", Root: "/"}},
		observe.Observed{Path: "/sys/fs/cgroup/cgroup.procs", Writable: true},
	)
	devs, anns := cgroupDelegation(obs)
	if devs != nil || anns != nil {
		t.Errorf("empty cgroup path should produce no output; got devs=%+v anns=%+v", devs, anns)
	}
}

func TestCgroupDelegation_NonCgroupPathsIgnored(t *testing.T) {
	cg := observe.CgroupInfo{Path: "/x"}
	mounts := []observe.MountInfo{{MountPoint: "/", Root: "/"}}
	obs := observedSetWithCgroup(cg, mounts,
		observe.Observed{Path: "/etc/passwd", Writable: true},
		observe.Observed{Path: "/proc/sysrq-trigger", Writable: true},
	)
	devs, anns := cgroupDelegation(obs)
	if len(devs) != 0 || len(anns) != 0 {
		t.Errorf("entries outside /sys/fs/cgroup should be ignored; got devs=%+v anns=%+v", devs, anns)
	}
}

func TestDiff_IntegratesCgroupResults(t *testing.T) {
	// End-to-end through Diff: cgroup exposure shows up in Deviations,
	// delegated-leaf in Annotations.
	intended := intendedSet()
	cg := observe.CgroupInfo{Path: "/container"}
	mounts := []observe.MountInfo{
		{MountID: 10, MountPoint: "/sys/fs/cgroup", Root: "/", VFSOptions: []string{"rw"}},
	}
	obs := observedSetWithCgroup(cg, mounts, observe.Observed{
		Path: "/sys/fs/cgroup/cgroup.procs", Writable: true,
	})
	res := Diff(intended, obs)
	if len(res.Deviations) != 1 || res.Deviations[0].Class != ClassCgroupDelegationExposure {
		t.Errorf("Deviations=%+v, want one CgroupDelegationExposure", res.Deviations)
	}
}
