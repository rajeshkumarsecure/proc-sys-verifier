package watch

import (
	"testing"
	"time"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

// withFrozenTime swaps nowFunc for the duration of fn so OccurredAt
// stamps are deterministic.
func withFrozenTime(t *testing.T, frozen time.Time, fn func()) {
	t.Helper()
	orig := nowFunc
	nowFunc = func() time.Time { return frozen }
	t.Cleanup(func() { nowFunc = orig })
	fn()
}

// makeSBMountEvent constructs a wire-compatible SBMountEvent for tests.
// `target` is null-padded into the Target array; target_len follows the
// kernel convention (length including trailing NUL).
func makeSBMountEvent(cgid uint64, pid, tgid uint32, comm, target string) SBMountEvent {
	ev := SBMountEvent{
		CgroupID: cgid,
		PID:      pid,
		TGID:     tgid,
	}
	copy(ev.Comm[:], comm)
	if target == "" {
		ev.TargetLen = -1 // kernel-style: negative => unresolved
	} else {
		copy(ev.Target[:], target)
		ev.TargetLen = int32(len(target) + 1) // +1 for NUL, matching bpf_d_path
	}
	return ev
}

func TestSBMountToDeviation_HappyPath(t *testing.T) {
	frozen, _ := time.Parse(time.RFC3339, "2026-06-01T15:00:00Z")
	withFrozenTime(t, frozen, func() {
		ev := makeSBMountEvent(42, 5601, 5601, "mount", "/proc/sys/kernel/hostname")
		dev := SBMountToDeviation(ev)

		if dev.Class != diff.ClassPostStartRemount {
			t.Errorf("Class=%s, want PostStartRemount", dev.Class)
		}
		if dev.Path != "/proc/sys/kernel/hostname" {
			t.Errorf("Path=%q", dev.Path)
		}
		obs, ok := dev.Observed.(diff.PostStartRemountObserved)
		if !ok {
			t.Fatalf("Observed type=%T", dev.Observed)
		}
		if obs.CgroupID != 42 || obs.ActorPID != 5601 || obs.ActorComm != "mount" {
			t.Errorf("Observed fields wrong: %+v", obs)
		}
		if obs.OccurredAt != frozen.Format(time.RFC3339Nano) {
			t.Errorf("OccurredAt=%q, want %q", obs.OccurredAt, frozen.Format(time.RFC3339Nano))
		}
		if obs.Truncated {
			t.Errorf("Truncated should be false on resolved path")
		}
	})
}

func TestSBMountToDeviation_TruncatedSetsFlagAndUnresolvedPath(t *testing.T) {
	// Kernel couldn't resolve the target — TargetLen <= 0.
	ev := makeSBMountEvent(42, 5601, 5601, "mount", "")
	dev := SBMountToDeviation(ev)
	obs := dev.Observed.(diff.PostStartRemountObserved)
	if !obs.Truncated {
		t.Errorf("Truncated should be true when TargetLen<=0")
	}
	// We still emit a Deviation so consumers see the cgroup + actor;
	// the Path field gets a placeholder so the renderer's grouping
	// doesn't barf on an empty key.
	if dev.Path != "(unresolved)" {
		t.Errorf("Path=%q, want sentinel '(unresolved)'", dev.Path)
	}
}

func makeFileOpenEvent(cgid uint64, handle uint32, cls PolicyClass, target string) FileOpenEvent {
	ev := FileOpenEvent{
		CgroupID:        cgid,
		PID:             5602,
		TGID:            5602,
		ContainerHandle: handle,
		PolicyClass:     uint8(cls),
	}
	copy(ev.Comm[:], "sh")
	copy(ev.Target[:], target)
	ev.TargetLen = int32(len(target) + 1)
	return ev
}

func TestFileOpenToDeviation_MaskedClass(t *testing.T) {
	ev := makeFileOpenEvent(42, 0, PolicyMasked, "/proc/sys/kernel/hostname")
	dev := FileOpenToDeviation(ev)

	if dev.Class != diff.ClassRuntimeWrite {
		t.Errorf("Class=%s, want RuntimeWrite", dev.Class)
	}
	intended := dev.Intended.(diff.RuntimeWriteIntended)
	if intended.Class != "masked" {
		t.Errorf("intended.Class=%q, want 'masked'", intended.Class)
	}
	obs := dev.Observed.(diff.RuntimeWriteObserved)
	if obs.ActorComm != "sh" || obs.CgroupID != 42 {
		t.Errorf("Observed fields wrong: %+v", obs)
	}
}

func TestFileOpenToDeviation_ReadOnlyClass(t *testing.T) {
	ev := makeFileOpenEvent(42, 1, PolicyReadOnly, "/proc/cmdline")
	dev := FileOpenToDeviation(ev)
	if dev.Intended.(diff.RuntimeWriteIntended).Class != "readonly" {
		t.Errorf("PolicyReadOnly should map to 'readonly'")
	}
}
