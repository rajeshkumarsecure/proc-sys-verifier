package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"json": FormatJSON,
		"JSON": FormatJSON,
		"tty":  FormatTTY,
		"TTY":  FormatTTY,
		"text": FormatTTY,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat(xml): want error, got nil")
	}
}

func TestRender_JSON_StableShape(t *testing.T) {
	r := diff.Report{
		ContainerID: "demo",
		InitPID:     42,
		Deviations: []diff.Deviation{
			{Class: diff.ClassWritableDrift, Path: "/proc/kcore",
				Observed: diff.WritableDriftObserved{Mode: "-rw-r--r--", Writable: true},
				Intended: diff.WritableDriftIntended{Kind: "masked"}},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, Options{Format: FormatJSON}); err != nil {
		t.Fatalf("Render JSON: %v", err)
	}
	s := buf.String()
	for _, want := range []string{
		`"container_id": "demo"`,
		`"init_pid": 42`,
		`"class": "WritableDrift"`,
		`"path": "/proc/kcore"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON missing %s\n%s", want, s)
		}
	}
}

func TestRender_JSON_DefaultFormat(t *testing.T) {
	// Empty Options.Format must default to JSON for backwards-compat with
	// any caller that builds Options without setting Format.
	var buf bytes.Buffer
	r := diff.Report{ContainerID: "x"}
	if err := Render(&buf, r, Options{}); err != nil {
		t.Fatalf("Render(default): %v", err)
	}
	if !strings.Contains(buf.String(), `"container_id": "x"`) {
		t.Errorf("default format != JSON: %q", buf.String())
	}
}

func TestRender_TTY_NoDeviations(t *testing.T) {
	var buf bytes.Buffer
	r := diff.Report{ContainerID: "demo123456789ABCDEF", InitPID: 99}
	if err := Render(&buf, r, Options{Format: FormatTTY}); err != nil {
		t.Fatalf("Render TTY: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, "container demo123456") {
		t.Errorf("missing truncated ID: %q", s)
	}
	if !strings.Contains(s, "init pid 99") {
		t.Errorf("missing pid: %q", s)
	}
	if !strings.Contains(s, "no deviations") {
		t.Errorf("missing clean-baseline line: %q", s)
	}
}

func TestRender_TTY_GroupedAndCounted(t *testing.T) {
	r := diff.Report{
		ContainerID: "demo",
		InitPID:     1,
		Deviations: []diff.Deviation{
			{Class: diff.ClassWritableDrift, Path: "/proc/kcore"},
			{Class: diff.ClassWritableDrift, Path: "/proc/keys"},
			{Class: diff.ClassOutOfPolicyRedirect, Path: "/proc/redirect", Rule: "deny:0:/proc/*"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, Options{Format: FormatTTY}); err != nil {
		t.Fatalf("Render TTY: %v", err)
	}
	s := buf.String()
	for _, want := range []string{
		"WRITABLE DRIFT  (2)",
		"OUT-OF-POLICY REDIRECT  (1)",
		"/proc/kcore",
		"/proc/keys",
		"/proc/redirect",
		"[deny:0:/proc/*]",
		"3 deviation(s) total",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("TTY missing %q\n%s", want, s)
		}
	}
}

func TestRender_TTY_ColorOff_NoEscapes(t *testing.T) {
	r := diff.Report{ContainerID: "x", InitPID: 1,
		Deviations: []diff.Deviation{{Class: diff.ClassWritableDrift, Path: "/p"}}}
	var buf bytes.Buffer
	if err := Render(&buf, r, Options{Format: FormatTTY, Color: false}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("color escapes leaked with Color=false: %q", buf.String())
	}
}

func TestRender_TTY_ColorOn_HasEscapes(t *testing.T) {
	r := diff.Report{ContainerID: "x", InitPID: 1,
		Deviations: []diff.Deviation{{Class: diff.ClassWritableDrift, Path: "/p"}}}
	var buf bytes.Buffer
	if err := Render(&buf, r, Options{Format: FormatTTY, Color: true}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("Color=true produced no ANSI escapes: %q", buf.String())
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, diff.Report{}, Options{Format: "xml"})
	if err == nil {
		t.Fatal("Render(unknown format): want error, got nil")
	}
}

func TestRender_TTY_UnknownClassFallback(t *testing.T) {
	// An unregistered class must not panic — fall back to a generic header.
	r := diff.Report{ContainerID: "x", Deviations: []diff.Deviation{
		{Class: diff.Class("InventedClass"), Path: "/p"},
	}}
	var buf bytes.Buffer
	if err := Render(&buf, r, Options{Format: FormatTTY}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "InventedClass") {
		t.Errorf("unknown class not surfaced: %q", buf.String())
	}
}

func TestRender_TTY_AnnotationsOnly_StillCleanBaseline(t *testing.T) {
	r := diff.Report{
		ContainerID: "demo",
		InitPID:     1,
		Annotations: []diff.Annotation{
			{Kind: diff.AnnotationDelegatedLeaf, Path: "/sys/fs/cgroup/cgroup.procs", Message: "delegated subtree"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, Options{Format: FormatTTY}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := buf.String()
	for _, want := range []string{
		"no deviations — contract intact",
		"CONTEXT  (1)",
		"safe-but-noteworthy",
		"DelegatedLeaf",
		"/sys/fs/cgroup/cgroup.procs",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("TTY missing %q\n%s", want, s)
		}
	}
}

func TestRender_TTY_DeviationsAndAnnotationsCoexist(t *testing.T) {
	r := diff.Report{
		ContainerID: "x", InitPID: 1,
		Deviations: []diff.Deviation{
			{Class: diff.ClassCgroupDelegationExposure, Path: "/sys/fs/cgroup/cgroup.subtree_control"},
		},
		Annotations: []diff.Annotation{
			{Kind: diff.AnnotationDelegatedLeaf, Path: "/sys/fs/cgroup/cgroup.procs", Message: "leaf"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, Options{Format: FormatTTY}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := buf.String()
	for _, want := range []string{
		"CGROUP DELEGATION EXPOSURE",
		"cgroup.subtree_control",
		"CONTEXT  (1)",
		"DelegatedLeaf",
		"1 deviation(s) total",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("TTY missing %q\n%s", want, s)
		}
	}
}

func TestShort(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"short":        "short",
		"abcdef123456": "abcdef123456",  // exactly 12
		"abcdef1234567890": "abcdef123456", // truncated
	}
	for in, want := range cases {
		if got := short(in); got != want {
			t.Errorf("short(%q) = %q, want %q", in, got, want)
		}
	}
}
