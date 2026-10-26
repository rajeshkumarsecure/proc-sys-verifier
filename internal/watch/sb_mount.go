// sb_mount.go — slice 21 LSM-hook loader. Watches a set of cgroups
// for mount(2)-class syscalls whose target resolves under /proc or
// /sys, and emits one PostStartRemount event per match.
//
// Pattern mirrors hello.go from slice 20: NewSBMount → Read → Close,
// with the addition of per-container map management (Watch /
// Unwatch). The watched set is mutable at runtime; callers add cgroup
// IDs as containers come up and remove them as containers exit.
//
// cgroup ID resolution: see CgroupIDFromPath. The kernel cgroup ID
// (what bpf_get_current_cgroup_id() returns inside the probe) is the
// inode number of the cgroup directory on the host, NOT the namespace
// ID Phase 2 captures. The two pieces of identity coexist; slice 21
// uses the kernel ID for in-kernel filtering, Phase 2 keeps the
// namespace ID for the observer's policy classifier.

package watch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// SBMountEvent mirrors struct sbmount_event in bpf/sb_mount/sb_mount.bpf.c.
// Layout is fixed-size with natural alignment; this struct is what the
// kernel writes into the ringbuf reservation.
type SBMountEvent struct {
	CgroupID  uint64
	PID       uint32
	TGID      uint32
	TargetLen int32 // bpf_d_path return value: length on success, negative errno on failure
	Comm      [16]byte
	Target    [256]byte
}

// CommString returns the comm field as a Go string, trimmed at the
// first NUL.
func (e *SBMountEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// TargetString returns the resolved mount target as a Go string.
// Empty when bpf_d_path failed (TargetLen <= 0).
func (e *SBMountEvent) TargetString() string {
	if e.TargetLen <= 0 {
		return ""
	}
	// bpf_d_path returns length including the trailing NUL; trim it.
	n := int(e.TargetLen) - 1
	if n > len(e.Target) {
		n = len(e.Target)
	}
	if n < 0 {
		n = 0
	}
	return string(e.Target[:n])
}

// Truncated returns true when the kernel couldn't resolve the mount
// target (path too long, dentry detached, etc.). The event was still
// emitted so userspace knows something happened in the watched
// container; the caller should re-scan to recover the missing detail.
func (e *SBMountEvent) Truncated() bool {
	return e.TargetLen <= 0
}

// SBMount is an attached lsm/sb_mount probe with its watched-cgroups
// map and ringbuf reader. Construct via NewSBMount; release via Close.
//
// The struct is not safe for concurrent use from multiple goroutines
// other than (a) Watch/Unwatch and (b) a single Read loop.
type SBMount struct {
	objs    sbmountObjects
	link    link.Link
	reader  *ringbuf.Reader
	rawSize int
}

// NewSBMount loads the BPF object, populates the watched-cgroups map
// with the given initial set, attaches the LSM hook, and opens the
// ringbuf reader. Returns an error if any step fails; partial state
// is cleaned up before returning.
//
// Requires the kernel cmdline to include `bpf` in the LSM list; see
// scripts/enable-bpf-lsm.sh. NewSBMount checks that prerequisite and
// returns ErrBPFLSMNotEnabled with a pointer at the helper.
func NewSBMount(watchedCgroupIDs []uint64) (*SBMount, error) {
	if err := checkBPFLSMEnabled(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}

	var objs sbmountObjects
	if err := loadSbmountObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loadSbmountObjects: %w", err)
	}

	// Populate watched set before attaching the hook — once attached,
	// every mount call gets checked; if the map is empty all events
	// drop, which is the safe default but not what the caller asked
	// for.
	one := uint8(1)
	for _, id := range watchedCgroupIDs {
		if err := objs.WatchedCgroups.Put(&id, &one); err != nil {
			objs.Close()
			return nil, fmt.Errorf("populate watched_cgroups: %w", err)
		}
	}

	lsm, err := link.AttachLSM(link.LSMOptions{Program: objs.PsvSbMount})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("AttachLSM(sb_mount): %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		lsm.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &SBMount{
		objs:    objs,
		link:    lsm,
		reader:  rd,
		rawSize: binary.Size(SBMountEvent{}),
	}, nil
}

// Watch adds a cgroup ID to the watched set. Subsequent mount calls
// from tasks in that cgroup will be considered. Idempotent: adding an
// already-watched ID is a no-op.
func (s *SBMount) Watch(cgroupID uint64) error {
	one := uint8(1)
	if err := s.objs.WatchedCgroups.Put(&cgroupID, &one); err != nil {
		return fmt.Errorf("watch cgroup %d: %w", cgroupID, err)
	}
	return nil
}

// Unwatch removes a cgroup ID from the watched set. Idempotent:
// removing an absent ID is a no-op.
func (s *SBMount) Unwatch(cgroupID uint64) error {
	if err := s.objs.WatchedCgroups.Delete(&cgroupID); err != nil {
		// ENOENT is fine — the contract is "after this call, the
		// cgroup is not in the watched set."
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("unwatch cgroup %d: %w", cgroupID, err)
	}
	return nil
}

// Read blocks until the next event arrives or the reader is closed.
// Returns io.EOF after Close.
func (s *SBMount) Read() (SBMountEvent, error) {
	var ev SBMountEvent
	record, err := s.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ev, io.EOF
		}
		return ev, fmt.Errorf("ringbuf.Read: %w", err)
	}
	if len(record.RawSample) < s.rawSize {
		return ev, fmt.Errorf("short ringbuf record: %d < %d", len(record.RawSample), s.rawSize)
	}
	if err := binary.Read(byteReader(record.RawSample[:s.rawSize]), nativeEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode event: %w", err)
	}
	return ev, nil
}

// Close detaches the probe and frees kernel resources. Safe to call
// multiple times; subsequent calls are no-ops.
func (s *SBMount) Close() error {
	var errs []error
	if s.reader != nil {
		if err := s.reader.Close(); err != nil {
			errs = append(errs, err)
		}
		s.reader = nil
	}
	if s.link != nil {
		if err := s.link.Close(); err != nil {
			errs = append(errs, err)
		}
		s.link = nil
	}
	if err := s.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("close: %v", errs)
	}
	return nil
}
