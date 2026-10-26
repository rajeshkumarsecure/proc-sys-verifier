package main

import (
	"strings"
	"testing"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

// Exercises the JSONL → []Deviation decoder. Covers:
//   - the happy path for both Phase 4 classes (PostStartRemount,
//     RuntimeWrite), confirming Observed/Intended typed payloads
//     survive the round-trip;
//   - container ID filtering (events for OTHER containers are silently
//     dropped, which is the documented multi-tenant ingest contract);
//   - forward-compatibility for an unrecognized Class (raw payload
//     preserved instead of erroring out).
func TestDecodeWatchEvents_ClassDispatch(t *testing.T) {
	in := strings.Join([]string{
		// PostStartRemount for our container — keep.
		`{"container_id":"demo","deviation":{"class":"PostStartRemount","path":"/proc/sysrq-trigger","observed":{"cgroup_id":42,"actor_pid":5601,"actor_comm":"exploit.sh","occurred_at":"2026-06-01T14:22:08.412Z"},"intended":{"class":"masked"}}}`,
		// RuntimeWrite for our container — keep.
		`{"container_id":"demo","deviation":{"class":"RuntimeWrite","path":"/proc/sys/kernel/core_pattern","observed":{"cgroup_id":42,"actor_pid":5602,"actor_comm":"sh"},"intended":{"class":"masked"}}}`,
		// Event for a different container — drop silently.
		`{"container_id":"other","deviation":{"class":"PostStartRemount","path":"/proc/whatever","observed":{},"intended":{}}}`,
		// Unknown class — forward-compat path; keep but pass payload through.
		`{"container_id":"demo","deviation":{"class":"FutureClassThatDoesntExist","path":"/x","observed":{"a":1},"intended":{"b":2}}}`,
		// Blank line — should be skipped, not error.
		``,
	}, "\n")

	devs, err := decodeWatchEvents(strings.NewReader(in), "demo")
	if err != nil {
		t.Fatalf("decodeWatchEvents: %v", err)
	}
	if len(devs) != 3 {
		t.Fatalf("got %d deviations, want 3 (PostStartRemount, RuntimeWrite, FutureClass)", len(devs))
	}

	// 1: PostStartRemount typed decode.
	psr := devs[0]
	if psr.Class != diff.ClassPostStartRemount {
		t.Errorf("devs[0].Class = %s, want PostStartRemount", psr.Class)
	}
	if psr.Path != "/proc/sysrq-trigger" {
		t.Errorf("devs[0].Path = %q", psr.Path)
	}
	psrObs, ok := psr.Observed.(diff.PostStartRemountObserved)
	if !ok {
		t.Fatalf("devs[0].Observed type = %T, want PostStartRemountObserved", psr.Observed)
	}
	if psrObs.ActorPID != 5601 || psrObs.ActorComm != "exploit.sh" || psrObs.CgroupID != 42 {
		t.Errorf("PostStartRemount observed payload corrupted: %+v", psrObs)
	}

	// 2: RuntimeWrite typed decode.
	rw := devs[1]
	if rw.Class != diff.ClassRuntimeWrite {
		t.Errorf("devs[1].Class = %s, want RuntimeWrite", rw.Class)
	}
	rwInt, ok := rw.Intended.(diff.RuntimeWriteIntended)
	if !ok {
		t.Fatalf("devs[1].Intended type = %T, want RuntimeWriteIntended", rw.Intended)
	}
	if rwInt.Class != "masked" {
		t.Errorf("RuntimeWrite intended.class = %q, want masked", rwInt.Class)
	}

	// 3: forward-compat (unknown class) — Observed/Intended kept as
	// json.RawMessage so a downstream renderer can show what's there
	// without us hard-coding the new type.
	fc := devs[2]
	if string(fc.Class) != "FutureClassThatDoesntExist" {
		t.Errorf("devs[2].Class = %q", fc.Class)
	}
	if fc.Path != "/x" {
		t.Errorf("devs[2].Path = %q", fc.Path)
	}
}

func TestDecodeWatchEvents_MalformedLineErrors(t *testing.T) {
	// A line that isn't valid JSON at all should produce a useful error
	// (with line number) rather than swallowing the rest of the file.
	in := strings.NewReader("not json at all\n")
	if _, err := decodeWatchEvents(in, "demo"); err == nil {
		t.Fatal("expected error on malformed JSONL, got nil")
	} else if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("error should mention line number; got: %v", err)
	}
}

// mergeWatchDeviations preserves input order within the same (class,
// path) bucket — important because watch events are chronological and
// the renderer's grouping displays them in that order.
func TestMergeWatchDeviations_StableByClassPath(t *testing.T) {
	base := []diff.Deviation{
		{Class: diff.ClassWritableDrift, Path: "/proc/foo"},
		{Class: diff.ClassCgroupDelegationExposure, Path: "/sys/fs/cgroup/cgroup.procs"},
	}
	extras := []diff.Deviation{
		// Two RuntimeWrite events on the same path; chronological order
		// must be preserved (first-emitted event sorts first).
		{Class: diff.ClassRuntimeWrite, Path: "/proc/X", Observed: diff.RuntimeWriteObserved{OccurredAt: "T1"}},
		{Class: diff.ClassRuntimeWrite, Path: "/proc/X", Observed: diff.RuntimeWriteObserved{OccurredAt: "T2"}},
		{Class: diff.ClassPostStartRemount, Path: "/proc/A"},
	}
	merged := mergeWatchDeviations(base, extras)

	if len(merged) != 5 {
		t.Fatalf("got %d, want 5", len(merged))
	}
	// Expected class order: CgroupDelegationExposure < PostStartRemount <
	// RuntimeWrite < WritableDrift (lexicographic on the Class string).
	wantOrder := []struct {
		class diff.Class
		path  string
	}{
		{diff.ClassCgroupDelegationExposure, "/sys/fs/cgroup/cgroup.procs"},
		{diff.ClassPostStartRemount, "/proc/A"},
		{diff.ClassRuntimeWrite, "/proc/X"}, // first-emitted preserved by stable sort
		{diff.ClassRuntimeWrite, "/proc/X"},
		{diff.ClassWritableDrift, "/proc/foo"},
	}
	for i, want := range wantOrder {
		if merged[i].Class != want.class || merged[i].Path != want.path {
			t.Errorf("merged[%d] = {%s %s}, want {%s %s}",
				i, merged[i].Class, merged[i].Path, want.class, want.path)
		}
	}
	// Verify chronological stability within (RuntimeWrite, /proc/X).
	t1 := merged[2].Observed.(diff.RuntimeWriteObserved).OccurredAt
	t2 := merged[3].Observed.(diff.RuntimeWriteObserved).OccurredAt
	if t1 != "T1" || t2 != "T2" {
		t.Errorf("chronological order broken: got T1=%q T2=%q", t1, t2)
	}
}

func TestMergeWatchDeviations_EmptyExtrasShortCircuit(t *testing.T) {
	base := []diff.Deviation{{Class: diff.ClassWritableDrift, Path: "/proc/foo"}}
	got := mergeWatchDeviations(base, nil)
	// Identity preserved when there's nothing to merge — avoids an
	// unnecessary copy + sort on the hot ingest path.
	if len(got) != len(base) {
		t.Errorf("len changed: got %d, want %d", len(got), len(base))
	}
}
