package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/discover"
)

// fakeSource is a discover.Source that returns a fixed list, for testing cmdList
// without depending on runc being installed on the host.
type fakeSource struct {
	name string
	list []discover.Container
}

func (f *fakeSource) Name() string                                             { return f.name }
func (f *fakeSource) Available(ctx context.Context) bool                       { return true }
func (f *fakeSource) List(ctx context.Context) ([]discover.Container, error)   { return f.list, nil }

// erroringSource lets a test assert discovery-error surfacing in cmdList/cmdObserve.
type erroringSource struct{ err error }

func (e *erroringSource) Name() string                            { return "erroring" }
func (e *erroringSource) Available(ctx context.Context) bool      { return true }
func (e *erroringSource) List(ctx context.Context) ([]discover.Container, error) {
	return nil, e.err
}

// withEuid temporarily overrides the geteuid hook for a test.
func withEuid(t *testing.T, uid int) {
	t.Helper()
	orig := geteuid
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = orig })
}

func TestRun_NoArgs(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run(nil, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "Usage:") {
		t.Fatalf("stderr missing usage: %q", errBuf.String())
	}
}

func TestRun_Help(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := run([]string{arg}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			if !strings.Contains(out.String(), "Usage:") {
				t.Fatalf("stdout missing usage: %q", out.String())
			}
		})
	}
}

func TestRun_Version(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"version"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "psv ") {
		t.Fatalf("stdout = %q, want prefix 'psv '", out.String())
	}
}

func TestRun_VersionShort(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"version", "-short"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	got := strings.TrimSpace(out.String())
	if got != version {
		t.Fatalf("stdout = %q, want %q", got, version)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"nope"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "unknown command") {
		t.Fatalf("stderr = %q, want unknown-command message", errBuf.String())
	}
}

func TestRun_InspectSpec_Fixture(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"inspect-spec", "../../internal/spec/testdata/runc-default-config.json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	for _, want := range []string{`"/proc/kcore"`, `"masked"`, `"/proc/sys"`, `"readonly"`, `"/sys/fs/cgroup"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %s", want)
		}
	}
}

func TestRun_InspectSpec_MissingArg(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"inspect-spec"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_InspectSpec_MissingFile(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"inspect-spec", "/no/such/file.json"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, errBuf.String())
	}
}

func TestCmdList_Table(t *testing.T) {
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "abcdef1234567890", Runtime: "runc", Status: "running", InitPID: 4242, BundlePath: "/run/runc/x"},
	}}
	var out, errBuf bytes.Buffer
	code := cmdList(nil, &out, &errBuf, []discover.Source{src})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	for _, want := range []string{"ID", "RUNTIME", "abcdef123456", "runc", "running", "4242", "/run/runc/x"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q\n--- got ---\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "7890") {
		t.Errorf("ID not truncated:\n%s", out.String())
	}
}

func TestCmdList_JSON(t *testing.T) {
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "abc", Runtime: "runc", InitPID: 1},
	}}
	var out, errBuf bytes.Buffer
	code := cmdList([]string{"-json"}, &out, &errBuf, []discover.Source{src})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	for _, want := range []string{`"id": "abc"`, `"runtime": "runc"`, `"init_pid": 1`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q\n--- got ---\n%s", want, out.String())
		}
	}
}

func TestCmdList_Empty(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := cmdList(nil, &out, &errBuf, []discover.Source{&fakeSource{name: "fake"}})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "no containers found") {
		t.Errorf("output = %q, want 'no containers found'", out.String())
	}
}

func TestCmdObserve_MissingArg(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := cmdObserve(nil, &out, &errBuf, []discover.Source{&fakeSource{name: "fake"}})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr=%q", code, errBuf.String())
	}
}

func TestCmdObserve_NoSuchContainer(t *testing.T) {
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "abc", Runtime: "runc", InitPID: 1},
	}}
	var out, errBuf bytes.Buffer
	code := cmdObserve([]string{"zzz"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "no container matches") {
		t.Errorf("stderr=%q, want 'no container matches'", errBuf.String())
	}
}

// TestCmdObserve_PrefixMatch covers the prefix-resolution branch of cmdObserve
// (an ID prefix of length >=4 matches the full container ID). The observer
// itself then fails (we have no live container), but the prefix-match path is
// what's under test.
func TestCmdObserve_PrefixMatch(t *testing.T) {
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "abcdef1234567890", Runtime: "runc", InitPID: 999999, NSPaths: map[string]string{
			"mnt": "/proc/999999/ns/mnt",
		}},
	}}
	var out, errBuf bytes.Buffer
	// "abcd" is a 4-char prefix of the container ID above.
	code := cmdObserve([]string{"abcd"}, &out, &errBuf, []discover.Source{src})
	// Container was found (no "no container matches" message), but observe
	// failed because we don't have a live ns. That proves the resolution
	// path executed.
	if strings.Contains(errBuf.String(), "no container matches") {
		t.Fatalf("prefix match did not resolve: stderr=%q", errBuf.String())
	}
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero (observe should fail on bogus pid); stderr=%q", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "psv: observe:") {
		t.Errorf("stderr=%q, want 'psv: observe:' prefix", errBuf.String())
	}
}

// TestCmdObserve_ShortIDExact covers the exact-match branch when the ID is
// shorter than the 4-char prefix threshold.
func TestCmdObserve_ShortIDExact(t *testing.T) {
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "x", Runtime: "runc", InitPID: 999998, NSPaths: map[string]string{
			"mnt": "/proc/999998/ns/mnt",
		}},
	}}
	var out, errBuf bytes.Buffer
	code := cmdObserve([]string{"x"}, &out, &errBuf, []discover.Source{src})
	if strings.Contains(errBuf.String(), "no container matches") {
		t.Fatalf("exact match did not resolve: stderr=%q", errBuf.String())
	}
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero; stderr=%q", errBuf.String())
	}
}

// TestTruncateID covers both branches of the helper.
func TestTruncateID(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"short":         "short",
		"abcdef123456":  "abcdef123456", // exactly 12
		"abcdef1234567": "abcdef123456", // 13 → truncated
	}
	for in, want := range cases {
		if got := truncateID(in); got != want {
			t.Errorf("truncateID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCmdList_RootHint_NonRoot ensures the sudo nudge is printed when no
// containers found AND we're not root.
func TestCmdList_RootHint_NonRoot(t *testing.T) {
	withEuid(t, 1000)
	var out, errBuf bytes.Buffer
	code := cmdList(nil, &out, &errBuf, []discover.Source{&fakeSource{name: "fake"}})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "no containers found") {
		t.Errorf("stdout = %q, want 'no containers found'", out.String())
	}
	if !strings.Contains(errBuf.String(), "hint: psv usually needs root") {
		t.Errorf("stderr = %q, want root hint", errBuf.String())
	}
}

// TestCmdList_NoHintWhenRoot ensures we do NOT print the hint as root.
func TestCmdList_NoHintWhenRoot(t *testing.T) {
	withEuid(t, 0)
	var out, errBuf bytes.Buffer
	cmdList(nil, &out, &errBuf, []discover.Source{&fakeSource{name: "fake"}})
	if strings.Contains(errBuf.String(), "hint:") {
		t.Errorf("stderr = %q, want no hint when euid=0", errBuf.String())
	}
}

// TestCmdObserve_SurfaceDiscoveryError checks that when discovery fails and
// no match is found, the failure message says so explicitly.
func TestCmdObserve_SurfaceDiscoveryError(t *testing.T) {
	withEuid(t, 0) // suppress the root hint to isolate this assertion
	src := &erroringSource{err: errors.New("simulated permission denied")}
	var out, errBuf bytes.Buffer
	code := cmdObserve([]string{"demo"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errBuf.String(), "simulated permission denied") {
		t.Errorf("stderr=%q, want raw discovery error surfaced", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "discovery had errors above") {
		t.Errorf("stderr=%q, want 'discovery had errors above' in no-match message", errBuf.String())
	}
}

// TestCmdObserve_RootHint_NonRoot covers the same nudge in the observe path.
func TestCmdObserve_RootHint_NonRoot(t *testing.T) {
	withEuid(t, 1000)
	src := &fakeSource{name: "fake"} // empty list
	var out, errBuf bytes.Buffer
	code := cmdObserve([]string{"demo"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errBuf.String(), "no container matches") {
		t.Errorf("stderr=%q, want 'no container matches'", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "hint: psv usually needs root") {
		t.Errorf("stderr=%q, want root hint", errBuf.String())
	}
}

func TestCmdScan_MissingArg(t *testing.T) {
	withEuid(t, 0)
	var out, errBuf bytes.Buffer
	code := cmdScan(nil, &out, &errBuf, []discover.Source{&fakeSource{name: "fake"}})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestCmdScan_NoSuchContainer(t *testing.T) {
	withEuid(t, 0)
	src := &fakeSource{name: "fake", list: []discover.Container{{ID: "abc"}}}
	var out, errBuf bytes.Buffer
	code := cmdScan([]string{"zzz"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "no container matches") {
		t.Errorf("stderr=%q, want 'no container matches'", errBuf.String())
	}
}

func TestCmdScan_MissingSpecPath(t *testing.T) {
	withEuid(t, 0)
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "demo", Runtime: "runc", InitPID: 1 /* no SpecPath */},
	}}
	var out, errBuf bytes.Buffer
	code := cmdScan([]string{"demo"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "no known OCI spec path") {
		t.Errorf("stderr=%q, want spec-path error", errBuf.String())
	}
}

func TestCmdScan_SpecLoadFails(t *testing.T) {
	withEuid(t, 0)
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "demo", Runtime: "runc", InitPID: 1, SpecPath: "/no/such/file.json"},
	}}
	var out, errBuf bytes.Buffer
	code := cmdScan([]string{"demo"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "load spec:") {
		t.Errorf("stderr=%q, want load-spec error", errBuf.String())
	}
}

func TestCmdScan_UnknownBuiltinPolicy(t *testing.T) {
	withEuid(t, 0)
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "demo", Runtime: "runc", InitPID: 1, SpecPath: "/no/such/file.json"},
	}}
	var out, errBuf bytes.Buffer
	code := cmdScan([]string{"-policy", "nope", "demo"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "load policy") {
		t.Errorf("stderr=%q, want load-policy error", errBuf.String())
	}
}

func TestCmdScan_PolicyFileMissing(t *testing.T) {
	withEuid(t, 0)
	src := &fakeSource{name: "fake", list: []discover.Container{
		{ID: "demo", Runtime: "runc", InitPID: 1, SpecPath: "/no/such/file.json"},
	}}
	var out, errBuf bytes.Buffer
	code := cmdScan([]string{"-policy-file", "/no/such/policy.yaml", "demo"}, &out, &errBuf, []discover.Source{src})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "load policy") {
		t.Errorf("stderr=%q, want load-policy error", errBuf.String())
	}
}

func TestCmdScan_UnknownFormat(t *testing.T) {
	withEuid(t, 0)
	src := &fakeSource{name: "fake", list: []discover.Container{{ID: "demo"}}}
	var out, errBuf bytes.Buffer
	code := cmdScan([]string{"-format", "xml", "demo"}, &out, &errBuf, []discover.Source{src})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "unknown format") {
		t.Errorf("stderr=%q, want 'unknown format'", errBuf.String())
	}
}

func TestIsTerminal_BytesBuffer(t *testing.T) {
	// *bytes.Buffer is the writer used in all unit tests; it must always
	// report not-a-terminal so we don't emit ANSI escapes into captured output.
	var buf bytes.Buffer
	if isTerminal(&buf) {
		t.Error("isTerminal(*bytes.Buffer) = true, want false")
	}
}

// TestFindContainer covers the resolution helper that backs both observe and scan.
func TestFindContainer(t *testing.T) {
	cs := []discover.Container{
		{ID: "abcdef1234567890"},
		{ID: "short"},
	}
	cases := []struct {
		want   string
		expect string // ID we expect to find, or "" for nil
	}{
		{"abcdef1234567890", "abcdef1234567890"}, // exact long
		{"short", "short"},                       // exact short
		{"abcd", "abcdef1234567890"},             // 4-char prefix matches
		{"abcdef", "abcdef1234567890"},           // longer prefix matches
		{"abc", ""},                              // 3-char prefix not enough
		{"zzz", ""},                              // no match
		{"shorter", ""},                          // longer than candidate
	}
	for _, c := range cases {
		got := findContainer(cs, c.want)
		if c.expect == "" {
			if got != nil {
				t.Errorf("findContainer(%q) = %+v, want nil", c.want, got)
			}
			continue
		}
		if got == nil || got.ID != c.expect {
			t.Errorf("findContainer(%q) = %+v, want id=%q", c.want, got, c.expect)
		}
	}
}
