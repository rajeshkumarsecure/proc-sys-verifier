package policy

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

func TestBuiltin_Default(t *testing.T) {
	p, err := Builtin("default")
	if err != nil {
		t.Fatalf("Builtin(default): %v", err)
	}
	if p.Name != "default" {
		t.Errorf("Name=%q, want default", p.Name)
	}
	// Default profile starts with no allow rules (no exceptions to the OCI
	// contract). Phase 4 added two deny rules so PostStartRemount and
	// RuntimeWrite events from `psv scan -ingest` land in the report
	// tagged with their rule names. Anything else here would suggest the
	// builtin drifted from its documented intent.
	if len(p.Allow) != 0 {
		t.Errorf("default profile should have no allow rules: allow=%d", len(p.Allow))
	}
	if len(p.Deny) != 2 {
		t.Errorf("default profile expects 2 deny rules (Phase 4 PostStartRemount + RuntimeWrite); got %d", len(p.Deny))
	}
	wantClasses := map[diff.Class]bool{
		diff.ClassPostStartRemount: false,
		diff.ClassRuntimeWrite:     false,
	}
	for _, r := range p.Deny {
		if _, ok := wantClasses[r.Class]; ok {
			wantClasses[r.Class] = true
		}
	}
	for cls, seen := range wantClasses {
		if !seen {
			t.Errorf("default profile missing deny rule for class %s", cls)
		}
	}
}

func TestBuiltin_Missing(t *testing.T) {
	if _, err := Builtin("nope"); err == nil {
		t.Fatal("Builtin(nope): want error, got nil")
	}
}

func TestBuiltinNames(t *testing.T) {
	names := BuiltinNames()
	if !slices.Contains(names, "default") {
		t.Errorf("BuiltinNames=%v, want to contain 'default'", names)
	}
}

func TestLoad_Valid(t *testing.T) {
	yaml := `
name: test
description: example
allow:
  - class: WritableDrift
    path_glob: /sys/fs/cgroup/**
    reason: cgroup delegation expected
deny:
  - class: WritableDrift
    path_glob: /proc/sys/kernel/*
    reason: must stay readonly
`
	p, err := Load(strings.NewReader(yaml), "test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Name != "test" || len(p.Allow) != 1 || len(p.Deny) != 1 {
		t.Fatalf("p=%+v", p)
	}
	if p.Allow[0].Name != "allow:0:/sys/fs/cgroup/**" {
		t.Errorf("Allow[0].Name=%q", p.Allow[0].Name)
	}
	if p.Deny[0].Name != "deny:0:/proc/sys/kernel/*" {
		t.Errorf("Deny[0].Name=%q", p.Deny[0].Name)
	}
}

func TestLoad_MissingName(t *testing.T) {
	if _, err := Load(strings.NewReader(`allow: []`), "test"); err == nil {
		t.Fatal("Load: want error for missing name")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	if _, err := Load(strings.NewReader("name: x\nallow: ["), "test"); err == nil {
		t.Fatal("Load: want parse error")
	}
}

func TestLoad_RuleMissingGlob(t *testing.T) {
	yaml := `
name: t
allow:
  - class: WritableDrift
    reason: missing glob
`
	if _, err := Load(strings.NewReader(yaml), "test"); err == nil {
		t.Fatal("Load: want validation error for missing path_glob")
	}
}

func TestLoad_RuleBadGlob(t *testing.T) {
	yaml := `
name: t
allow:
  - class: WritableDrift
    path_glob: "[unterminated"
`
	if _, err := Load(strings.NewReader(yaml), "test"); err == nil {
		t.Fatal("Load: want validation error for bad glob")
	}
}

func TestApply_NilProfile_PassThrough(t *testing.T) {
	devs := []diff.Deviation{{Class: diff.ClassWritableDrift, Path: "/x"}}
	got := Apply(nil, devs)
	if len(got) != 1 || got[0].Path != "/x" {
		t.Errorf("Apply(nil, ...) modified result: %+v", got)
	}
}

func TestApply_AllowSuppresses(t *testing.T) {
	p := &Profile{
		Name:  "t",
		Allow: []Rule{{Class: diff.ClassWritableDrift, PathGlob: "/sys/fs/cgroup/*", Name: "allow:0:/sys/fs/cgroup/*"}},
	}
	devs := []diff.Deviation{
		{Class: diff.ClassWritableDrift, Path: "/sys/fs/cgroup/cgroup.procs"},
		{Class: diff.ClassWritableDrift, Path: "/proc/sysrq-trigger"},
	}
	got := Apply(p, devs)
	if len(got) != 1 || got[0].Path != "/proc/sysrq-trigger" {
		t.Errorf("got=%+v, want only /proc/sysrq-trigger to survive", got)
	}
}

func TestApply_DenyTagsAndKeeps(t *testing.T) {
	p := &Profile{
		Name: "t",
		Deny: []Rule{{Class: diff.ClassWritableDrift, PathGlob: "/proc/sysrq-trigger", Name: "deny:0:/proc/sysrq-trigger"}},
	}
	devs := []diff.Deviation{{Class: diff.ClassWritableDrift, Path: "/proc/sysrq-trigger"}}
	got := Apply(p, devs)
	if len(got) != 1 {
		t.Fatalf("got=%+v", got)
	}
	if got[0].Rule != "deny:0:/proc/sysrq-trigger" {
		t.Errorf("Rule=%q, want deny rule name", got[0].Rule)
	}
}

func TestApply_DenyBeatsAllow(t *testing.T) {
	p := &Profile{
		Name: "t",
		Allow: []Rule{
			{Class: diff.ClassWritableDrift, PathGlob: "/sys/fs/cgroup/*", Name: "allow:0:/sys/fs/cgroup/*"},
		},
		Deny: []Rule{
			{Class: diff.ClassWritableDrift, PathGlob: "/sys/fs/cgroup/cgroup.subtree_control", Name: "deny:0:/sys/fs/cgroup/cgroup.subtree_control"},
		},
	}
	devs := []diff.Deviation{{Class: diff.ClassWritableDrift, Path: "/sys/fs/cgroup/cgroup.subtree_control"}}
	got := Apply(p, devs)
	if len(got) != 1 {
		t.Fatalf("got=%+v, want deny to win over allow", got)
	}
	if got[0].Rule == "" || !strings.HasPrefix(got[0].Rule, "deny:") {
		t.Errorf("Rule=%q, want a deny rule", got[0].Rule)
	}
}

func TestApply_EmptyClassMatchesAny(t *testing.T) {
	// A rule with no Class targets every class.
	p := &Profile{
		Name:  "t",
		Allow: []Rule{{PathGlob: "/proc/*", Name: "allow:0:/proc/*"}},
	}
	devs := []diff.Deviation{
		{Class: diff.ClassWritableDrift, Path: "/proc/kcore"},
		{Class: diff.ClassOutOfPolicyRedirect, Path: "/proc/redirect"},
	}
	got := Apply(p, devs)
	if len(got) != 0 {
		t.Errorf("got=%+v, want both suppressed", got)
	}
}

func TestApply_ClassMismatch_NoMatch(t *testing.T) {
	p := &Profile{
		Name:  "t",
		Allow: []Rule{{Class: diff.ClassOutOfPolicyRedirect, PathGlob: "/proc/*", Name: "allow:0:/proc/*"}},
	}
	devs := []diff.Deviation{{Class: diff.ClassWritableDrift, Path: "/proc/kcore"}}
	got := Apply(p, devs)
	if len(got) != 1 {
		t.Errorf("got=%+v, want WritableDrift to pass through (class mismatch)", got)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/p.yaml"
	if err := os.WriteFile(f, []byte("name: ondisk\nallow: []\ndeny: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadFile(f)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.Name != "ondisk" {
		t.Errorf("Name=%q, want ondisk", p.Name)
	}
}

func TestLoadFile_Missing(t *testing.T) {
	if _, err := LoadFile("/no/such/profile.yaml"); err == nil {
		t.Fatal("LoadFile: want error")
	}
}

// TestGlobMatch covers the doublestar extension to path.Match.
func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		// Plain path.Match — single segment only.
		{"/proc/kcore", "/proc/kcore", true},
		{"/proc/*", "/proc/kcore", true},
		{"/proc/*", "/proc/sys/kernel/hostname", false}, // * does not cross /
		// ** as recursive wildcard.
		{"/proc/**", "/proc/kcore", true},
		{"/proc/**", "/proc/sys/kernel/hostname", true},
		{"/proc/**", "/sys/firmware", false},
		// Mixed: prefix + ** + literal suffix.
		{"/sys/fs/cgroup/**", "/sys/fs/cgroup/cgroup.procs", true},
		{"/sys/fs/cgroup/**", "/sys/fs/cgroup", false}, // requires at least one char after the /
		{"/sys/fs/cgroup/**", "/sys/fs/cgroup/sub/dir/file", true},
		// Suffix only.
		{"**/cgroup.procs", "/sys/fs/cgroup/cgroup.procs", true},
		{"**/cgroup.procs", "/proc/kcore", false},
		// Middle segment.
		{"/sys/**/cgroup.procs", "/sys/fs/cgroup/cgroup.procs", true},
		{"/sys/**/cgroup.procs", "/proc/cgroup.procs", false},
		// Just "**" matches everything.
		{"**", "/proc/anything/deep/under/here", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.path); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestBuiltin_Privileged(t *testing.T) {
	p, err := Builtin("privileged")
	if err != nil {
		t.Fatalf("Builtin(privileged): %v", err)
	}
	if p.Name != "privileged" {
		t.Errorf("Name=%q", p.Name)
	}
	if len(p.Allow) == 0 {
		t.Errorf("privileged should have allow rules")
	}

	// WritableDrift inside /proc or /sys should be suppressed.
	devs := []diff.Deviation{
		{Class: diff.ClassWritableDrift, Path: "/proc/sysrq-trigger"},
		{Class: diff.ClassWritableDrift, Path: "/sys/kernel/profiling"},
		// OutOfPolicyRedirect under /proc must still pass through.
		{Class: diff.ClassOutOfPolicyRedirect, Path: "/proc/redirect"},
	}
	got := Apply(p, devs)
	if len(got) != 1 || got[0].Class != diff.ClassOutOfPolicyRedirect {
		t.Errorf("Apply(privileged): got=%+v, want only OutOfPolicyRedirect to survive", got)
	}
}

// makeCgroupDeviation builds a CgroupDelegationExposure deviation with the
// EffectivePath and ContainerCgroup the scope rules read.
func makeCgroupDeviation(path, effective, container string) diff.Deviation {
	return diff.Deviation{
		Class: diff.ClassCgroupDelegationExposure,
		Path:  path,
		Observed: diff.CgroupDelegationExposureObserved{
			File:            path,
			ContainerCgroup: container,
			EffectivePath:   effective,
		},
		Intended: diff.CgroupDelegationExposureIntended{
			DelegatedSubtree: container,
		},
	}
}

func TestLoad_ScopeOnly(t *testing.T) {
	// path_glob optional when scope is set.
	yamlSrc := `
name: t
allow:
  - class: CgroupDelegationExposure
    scope: delegated_subtree
`
	p, err := Load(strings.NewReader(yamlSrc), "test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(p.Allow) != 1 || p.Allow[0].Scope != ScopeDelegatedSubtree {
		t.Fatalf("Allow=%+v", p.Allow)
	}
	if !strings.Contains(p.Allow[0].Name, "scope=delegated_subtree") {
		t.Errorf("Name=%q should describe scope", p.Allow[0].Name)
	}
}

func TestLoad_RuleMissingGlobAndScope(t *testing.T) {
	yamlSrc := `
name: t
allow:
  - class: CgroupDelegationExposure
    reason: nothing to match on
`
	if _, err := Load(strings.NewReader(yamlSrc), "test"); err == nil {
		t.Fatal("Load: want error when neither path_glob nor scope is set")
	}
}

func TestLoad_UnknownScope(t *testing.T) {
	yamlSrc := `
name: t
allow:
  - class: CgroupDelegationExposure
    scope: not_a_scope
`
	if _, err := Load(strings.NewReader(yamlSrc), "test"); err == nil {
		t.Fatal("Load: want error for unknown scope")
	}
}

func TestApply_ScopeDelegatedSubtree_Suppresses(t *testing.T) {
	p := &Profile{
		Name: "t",
		Allow: []Rule{{
			Class: diff.ClassCgroupDelegationExposure,
			Scope: ScopeDelegatedSubtree,
			Name:  "allow:0:scope=delegated_subtree",
		}},
	}
	// EffectivePath inside ContainerCgroup → suppressed.
	d := makeCgroupDeviation("/sys/fs/cgroup/cgroup.procs",
		"/container/sub/cgroup.procs", "/container")
	if got := Apply(p, []diff.Deviation{d}); len(got) != 0 {
		t.Errorf("delegated-subtree deviation should be suppressed; got=%+v", got)
	}
}

func TestApply_ScopeAboveDelegatedRoot_TagsAndKeeps(t *testing.T) {
	p := &Profile{
		Name: "t",
		Deny: []Rule{{
			Class: diff.ClassCgroupDelegationExposure,
			Scope: ScopeAboveDelegatedRoot,
			Name:  "deny:0:scope=above_delegated_root",
		}},
	}
	d := makeCgroupDeviation("/sys/fs/cgroup/cgroup.subtree_control",
		"/cgroup.subtree_control", "/container")
	got := Apply(p, []diff.Deviation{d})
	if len(got) != 1 {
		t.Fatalf("got=%+v, want 1", got)
	}
	if got[0].Rule != "deny:0:scope=above_delegated_root" {
		t.Errorf("Rule=%q", got[0].Rule)
	}
}

func TestApply_ScopeOnWrongClass_NoMatch(t *testing.T) {
	// Scope rules read the cgroup payload; on a WritableDrift deviation
	// the type assertion fails so the rule cannot match. Deviation passes
	// through unchanged.
	p := &Profile{
		Name: "t",
		Allow: []Rule{{
			Class: "", // any class
			Scope: ScopeDelegatedSubtree,
			Name:  "allow:0:scope=delegated_subtree",
		}},
	}
	d := diff.Deviation{Class: diff.ClassWritableDrift, Path: "/proc/x"}
	if got := Apply(p, []diff.Deviation{d}); len(got) != 1 {
		t.Errorf("WritableDrift should not satisfy a cgroup-scope rule; got=%+v", got)
	}
}

func TestApply_ScopePlusGlob_BothMustMatch(t *testing.T) {
	// path_glob limits which cgroup files the scope rule applies to.
	p := &Profile{
		Name: "t",
		Deny: []Rule{{
			Class:    diff.ClassCgroupDelegationExposure,
			PathGlob: "/sys/fs/cgroup/cgroup.subtree_control",
			Scope:    ScopeAboveDelegatedRoot,
			Name:     "deny:0:strict",
		}},
	}
	// Outside delegated subtree, but path doesn't match the glob → pass through.
	d := makeCgroupDeviation("/sys/fs/cgroup/cgroup.procs",
		"/cgroup.procs", "/container")
	got := Apply(p, []diff.Deviation{d})
	if len(got) != 1 || got[0].Rule != "" {
		t.Errorf("non-matching glob should leave Rule empty; got=%+v", got)
	}
	// Same scope, matching glob → deny rule fires.
	d2 := makeCgroupDeviation("/sys/fs/cgroup/cgroup.subtree_control",
		"/cgroup.subtree_control", "/container")
	got = Apply(p, []diff.Deviation{d2})
	if len(got) != 1 || got[0].Rule != "deny:0:strict" {
		t.Errorf("matching glob+scope should fire deny; got=%+v", got)
	}
}

func TestBuiltin_SystemdCgroup(t *testing.T) {
	p, err := Builtin("systemd-cgroup")
	if err != nil {
		t.Fatalf("Builtin(systemd-cgroup): %v", err)
	}
	if p.Name != "systemd-cgroup" {
		t.Errorf("Name=%q", p.Name)
	}

	devs := []diff.Deviation{
		// Inside delegated subtree — expected, should be suppressed.
		makeCgroupDeviation("/sys/fs/cgroup/cgroup.procs",
			"/container/sub/cgroup.procs", "/container"),
		// Outside delegated subtree — flagged with the deny rule's name.
		makeCgroupDeviation("/sys/fs/cgroup/cgroup.subtree_control",
			"/cgroup.subtree_control", "/container"),
	}
	got := Apply(p, devs)
	if len(got) != 1 {
		t.Fatalf("got %d deviations, want 1 (the above-root one); %+v", len(got), got)
	}
	if !strings.HasPrefix(got[0].Rule, "deny:") {
		t.Errorf("surviving deviation should be tagged by the deny rule; Rule=%q", got[0].Rule)
	}
}

func TestIsInsideCgroup(t *testing.T) {
	cases := []struct {
		child, parent string
		want          bool
	}{
		{"/a/b", "/a", true},
		{"/a", "/a", true},
		{"/", "/", true},
		{"/x", "/", true},
		{"/ab", "/a", false}, // not a path-component prefix
		{"/a", "", false},    // empty parent rejected
		{"/a", "/b", false},
	}
	for _, c := range cases {
		if got := isInsideCgroup(c.child, c.parent); got != c.want {
			t.Errorf("isInsideCgroup(%q, %q) = %v, want %v", c.child, c.parent, got, c.want)
		}
	}
}
