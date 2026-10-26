package diff

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
)

func intendedSet(entries ...spec.Entry) *spec.IntendedSet {
	m := map[string]spec.Entry{}
	for _, e := range entries {
		m[e.Path] = e
	}
	return &spec.IntendedSet{Entries: m}
}

func observedSet(entries ...observe.Observed) *observe.ObservedSet {
	m := map[string]observe.Observed{}
	for _, e := range entries {
		m[e.Path] = e
	}
	return &observe.ObservedSet{Entries: m}
}

func TestDiff_Nil(t *testing.T) {
	if got := Diff(nil, nil); got.Deviations != nil || got.Annotations != nil {
		t.Errorf("Diff(nil, nil) = %+v, want empty Result", got)
	}
	if got := Diff(intendedSet(), nil); got.Deviations != nil || got.Annotations != nil {
		t.Errorf("Diff(empty, nil) = %+v, want empty Result", got)
	}
	if got := Diff(nil, observedSet()); got.Deviations != nil || got.Annotations != nil {
		t.Errorf("Diff(nil, empty) = %+v, want empty Result", got)
	}
}

func TestDiff_Empty(t *testing.T) {
	if got := Diff(intendedSet(), observedSet()); len(got.Deviations) != 0 {
		t.Errorf("Diff(empty, empty) = %+v, want empty", got)
	}
}

func TestDiff_MaskedWritable_FlagsDeviation(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{
		Path:     "/proc/kcore",
		Mode:     "-rw-r--r--",
		Writable: true,
		MountID:  42,
	})
	got := Diff(intended, observed).Deviations
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1; got=%+v", len(got), got)
	}
	d := got[0]
	if d.Class != ClassWritableDrift {
		t.Errorf("class=%q, want %q", d.Class, ClassWritableDrift)
	}
	if d.Path != "/proc/kcore" {
		t.Errorf("path=%q, want /proc/kcore", d.Path)
	}
	intended2, ok := d.Intended.(WritableDriftIntended)
	if !ok || intended2.Kind != "masked" {
		t.Errorf("intended=%+v, want kind=masked", d.Intended)
	}
	obs, ok := d.Observed.(WritableDriftObserved)
	if !ok || !obs.Writable || obs.MountID != 42 {
		t.Errorf("observed=%+v, want writable=true, mount_id=42", d.Observed)
	}
}

func TestDiff_ReadonlyWritable_FlagsDeviation(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/sys", Kind: spec.KindReadOnly})
	observed := observedSet(observe.Observed{
		Path: "/proc/sys", Mode: "drwxr-xr-x", Writable: true,
	})
	got := Diff(intended, observed).Deviations
	if len(got) != 1 || got[0].Path != "/proc/sys" || got[0].Class != ClassWritableDrift {
		t.Fatalf("got=%+v, want one WritableDrift on /proc/sys", got)
	}
}

func TestDiff_MaskedNotWritable_NoDeviation(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{
		Path: "/proc/kcore", Mode: "-r--r--r--", Writable: false,
	})
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation when masked path is not writable", got)
	}
}

func TestDiff_MountedWritable_NoDeviation(t *testing.T) {
	// Mounted paths derive writability from the operator-chosen mount
	// options. Writable mounted paths are NOT a WritableDrift on their own.
	intended := intendedSet(spec.Entry{
		Path: "/sys/fs/cgroup", Kind: spec.KindMounted,
		Type: "cgroup2", Source: "cgroup",
	})
	observed := observedSet(observe.Observed{
		Path: "/sys/fs/cgroup", Mode: "drwxr-xr-x", Writable: true,
	})
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation for writable mounted path", got)
	}
}

func TestDiff_IntendedButNotObserved_NoDeviation(t *testing.T) {
	// Masked path declared but absent inside the container (never mounted).
	// Other deviation classes may flag this later; WritableDrift does not.
	intended := intendedSet(spec.Entry{Path: "/proc/keys", Kind: spec.KindMasked})
	observed := observedSet()
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation when intended path is absent in observed", got)
	}
}

func TestDiff_StableOrder(t *testing.T) {
	// Provide entries in scrambled order; output must be sorted by Path.
	intended := intendedSet(
		spec.Entry{Path: "/proc/sysrq-trigger", Kind: spec.KindReadOnly},
		spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked},
		spec.Entry{Path: "/proc/keys", Kind: spec.KindMasked},
	)
	observed := observedSet(
		observe.Observed{Path: "/proc/kcore", Writable: true},
		observe.Observed{Path: "/proc/keys", Writable: true},
		observe.Observed{Path: "/proc/sysrq-trigger", Writable: true},
	)
	got := Diff(intended, observed).Deviations
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3", len(got))
	}
	wantPaths := []string{"/proc/kcore", "/proc/keys", "/proc/sysrq-trigger"}
	for i, p := range wantPaths {
		if got[i].Path != p {
			t.Errorf("got[%d].Path=%q, want %q", i, got[i].Path, p)
		}
	}
}

func TestDiff_JSONShape(t *testing.T) {
	// Check the JSON envelope matches the documented schema:
	//   {container_id, init_pid, deviations: [{class, path, observed, intended}]}
	intended := intendedSet(spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{Path: "/proc/kcore", Writable: true})
	res := Diff(intended, observed)
	report := Report{
		ContainerID: "demo",
		InitPID:     42,
		Deviations:  res.Deviations,
		Annotations: res.Annotations,
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"container_id":"demo"`,
		`"init_pid":42`,
		`"class":"WritableDrift"`,
		`"path":"/proc/kcore"`,
		`"intended":{"kind":"masked"}`,
		`"writable":true`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in JSON: %s", want, b)
		}
	}
}

func TestResolveLink(t *testing.T) {
	cases := []struct {
		linkPath, target, want string
	}{
		{"/proc/foo", "/etc/passwd", "/etc/passwd"},
		{"/proc/foo", "bar", "/proc/bar"},
		{"/proc/foo", "./bar", "/proc/bar"},
		{"/proc/sub/foo", "../bar", "/proc/bar"},
		{"/proc/sub/foo", "../../etc/passwd", "/etc/passwd"},
		{"/a/b/c", "/x/./y/../z", "/x/z"},     // absolute Clean
		{"/a/b/c", "../../..", "/"},            // resolves to root
	}
	for _, c := range cases {
		if got := resolveLink(c.linkPath, c.target); got != c.want {
			t.Errorf("resolveLink(%q, %q) = %q, want %q", c.linkPath, c.target, got, c.want)
		}
	}
}

func TestCoveringIntendedEntry(t *testing.T) {
	intended := intendedSet(
		spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked},
		spec.Entry{Path: "/proc/sys", Kind: spec.KindReadOnly},
		spec.Entry{Path: "/sys/firmware", Kind: spec.KindMasked},
	)
	cases := []struct {
		p       string
		wantOk  bool
		wantKnd spec.Kind
	}{
		{"/proc/kcore", true, spec.KindMasked},
		{"/proc/sys/kernel/hostname", true, spec.KindReadOnly}, // prefix match
		{"/sys/firmware/efi", true, spec.KindMasked},           // prefix match
		{"/proc/cpuinfo", false, ""},
		{"/etc/passwd", false, ""},
	}
	for _, c := range cases {
		e, ok := coveringIntendedEntry(intended, c.p)
		if ok != c.wantOk {
			t.Errorf("coveringIntendedEntry(%q): ok=%v, want %v", c.p, ok, c.wantOk)
			continue
		}
		if ok && e.Kind != c.wantKnd {
			t.Errorf("coveringIntendedEntry(%q): kind=%s, want %s", c.p, e.Kind, c.wantKnd)
		}
	}
}

func TestDiff_OutOfPolicyRedirect_AbsoluteToMasked(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{
		Path:       "/proc/redirect",
		Mode:       "Lrwxrwxrwx",
		IsSymlink:  true,
		LinkTarget: "/proc/kcore",
	})
	got := Diff(intended, observed).Deviations
	if len(got) != 1 {
		t.Fatalf("len=%d, want 1; got=%+v", len(got), got)
	}
	d := got[0]
	if d.Class != ClassOutOfPolicyRedirect {
		t.Errorf("class=%q, want %q", d.Class, ClassOutOfPolicyRedirect)
	}
	if d.Path != "/proc/redirect" {
		t.Errorf("path=%q, want /proc/redirect", d.Path)
	}
	obs, ok := d.Observed.(OutOfPolicyRedirectObserved)
	if !ok || obs.LinkTarget != "/proc/kcore" || obs.ResolvedTarget != "/proc/kcore" {
		t.Errorf("observed=%+v", d.Observed)
	}
	intd, ok := d.Intended.(OutOfPolicyRedirectIntended)
	if !ok || intd.TargetKind != "masked" {
		t.Errorf("intended=%+v", d.Intended)
	}
}

func TestDiff_OutOfPolicyRedirect_RelativeEscapeToMasked(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/sys/kernel", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{
		Path: "/proc/sys/foo/bar", Mode: "Lrwxrwxrwx", IsSymlink: true,
		LinkTarget: "../kernel/hostname", // ../kernel/hostname → /proc/sys/kernel/hostname
	})
	got := Diff(intended, observed).Deviations
	if len(got) != 1 || got[0].Class != ClassOutOfPolicyRedirect {
		t.Fatalf("got=%+v, want one OutOfPolicyRedirect", got)
	}
	obs := got[0].Observed.(OutOfPolicyRedirectObserved)
	if obs.ResolvedTarget != "/proc/sys/kernel/hostname" {
		t.Errorf("resolved=%q, want /proc/sys/kernel/hostname", obs.ResolvedTarget)
	}
}

func TestDiff_OutOfPolicyRedirect_TargetIsReadonly_NotFlagged(t *testing.T) {
	// Readonly targets are not flagged in v0: the ro bind survives the
	// dereference, so the symlink does not bypass anything.
	intended := intendedSet(spec.Entry{Path: "/proc/sys", Kind: spec.KindReadOnly})
	observed := observedSet(observe.Observed{
		Path: "/proc/redirect", Mode: "Lrwxrwxrwx", IsSymlink: true,
		LinkTarget: "/proc/sys/kernel/hostname",
	})
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation when target is readonly", got)
	}
}

func TestDiff_OutOfPolicyRedirect_TargetNotCovered_NotFlagged(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{
		Path: "/proc/redirect", Mode: "Lrwxrwxrwx", IsSymlink: true,
		LinkTarget: "/etc/passwd", // not in IntendedSet
	})
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation when resolved target not in IntendedSet", got)
	}
}

func TestDiff_OutOfPolicyRedirect_SelfLoop_NotFlagged(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{
		Path: "/proc/kcore", Mode: "Lrwxrwxrwx", IsSymlink: true,
		LinkTarget: "kcore", // resolves to itself
	})
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation for self-loop", got)
	}
}

func TestDiff_OutOfPolicyRedirect_LinkIsItselfMasked_NotFlagged(t *testing.T) {
	// If the symlink path is itself masked/readonly, WritableDrift handles
	// the case (if applicable). Don't double-count via OutOfPolicyRedirect.
	intended := intendedSet(
		spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked},
		spec.Entry{Path: "/proc/keys", Kind: spec.KindMasked},
	)
	observed := observedSet(observe.Observed{
		Path: "/proc/keys", Mode: "Lrwxrwxrwx", IsSymlink: true,
		LinkTarget: "/proc/kcore", // points into another masked path
	})
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation when link itself sits at a masked path", got)
	}
}

func TestDiff_OutOfPolicyRedirect_NotASymlink_NotFlagged(t *testing.T) {
	intended := intendedSet(spec.Entry{Path: "/proc/kcore", Kind: spec.KindMasked})
	observed := observedSet(observe.Observed{
		Path: "/proc/foo", LinkTarget: "/proc/kcore", // LinkTarget set but IsSymlink=false
	})
	if got := Diff(intended, observed).Deviations; len(got) != 0 {
		t.Errorf("got=%+v, want no deviation for non-symlink", got)
	}
}
