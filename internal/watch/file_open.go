// file_open.go — slice 22 LSM-hook loader. Watches a set of containers
// for writes against policy-protected paths (`maskedPaths` /
// `readonlyPaths` from the OCI spec) and emits one RuntimeWrite event
// per match.
//
// API shape mirrors slice 21's SBMount: NewFileOpen → Watch → Read →
// Close, with the addition of per-container LPM trie management
// embedded in Watch (each watched container needs its own intended-set
// trie registered in the outer ARRAY_OF_MAPS).
//
// Slice 23 will introduce a higher-level Watcher struct that drives
// both SBMount and FileOpen from a single Watch(container) call, but
// at the slice 22 layer the two probes have parallel-but-separate
// watched_cgroups maps for clean lifecycle and easier integration
// testing.

package watch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// FileOpenEvent mirrors struct fileopen_event in
// bpf/file_open/file_open.bpf.c. Field order, types, and lengths must
// stay in lockstep with the C struct; the kernel writes raw bytes into
// the ringbuf and we decode them with binary.Read.
type FileOpenEvent struct {
	CgroupID        uint64
	PID             uint32
	TGID            uint32
	ContainerHandle uint32
	PolicyClass     uint8
	_               [3]byte // alignment padding to match C struct; blank so encoding/binary skips it
	TargetLen       int32
	Comm            [16]byte
	Target          [LPMPathMax]byte
}

// CommString returns the comm field as a Go string, trimmed at the
// first NUL.
func (e *FileOpenEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// TargetString returns the resolved target path as a Go string.
// Empty when bpf_d_path failed (TargetLen <= 0).
func (e *FileOpenEvent) TargetString() string {
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

// Truncated returns true when the kernel couldn't resolve the file's
// path. The event is still emitted so userspace knows something
// happened in the watched container; the caller should re-scan.
func (e *FileOpenEvent) Truncated() bool {
	return e.TargetLen <= 0
}

// Class returns the PolicyClass enum for this event.
func (e *FileOpenEvent) Class() PolicyClass {
	return PolicyClass(e.PolicyClass)
}

// FileOpen is an attached lsm/file_open probe with its watched-cgroups
// map, per-container LPM tries, and ringbuf reader. Construct via
// NewFileOpen; release via Close.
//
// Watch / Unwatch are safe to call concurrently with Read from a single
// goroutine. Multi-goroutine Read is not supported.
type FileOpen struct {
	objs      fileopenObjects
	innerSpec *ebpf.MapSpec // template for creating per-container LPM tries
	link      link.Link
	reader    *ringbuf.Reader
	rawSize   int

	// innerMu protects the inner-map bookkeeping below. The BPF maps
	// themselves are safe for concurrent kernel access; this guards
	// only the userspace allocation of container_handle slots and the
	// inners map.
	innerMu sync.Mutex
	// inners holds the per-container LPM trie Map handles, keyed by
	// container_handle. We hold the handle to keep the inner map alive
	// (closing the last fd would free it); the kernel side sees it
	// through the outer ARRAY_OF_MAPS.
	inners map[uint32]*ebpf.Map
	// nextHandle is the next free index into the intended_sets outer
	// array. Monotonic; we don't reuse handles within a process lifetime
	// even after Unwatch, because handle reuse would require more
	// careful synchronization with in-flight events.
	nextHandle uint32
}

// NewFileOpen loads the BPF object, attaches the LSM hook, and opens
// the ringbuf reader. Watched cgroups start empty; call Watch for each
// container.
//
// Requires `bpf` in the kernel's active LSM list (same as slice 21);
// see scripts/enable-bpf-lsm.sh.
func NewFileOpen() (*FileOpen, error) {
	if err := checkBPFLSMEnabled(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}

	// Load the CollectionSpec first so we can capture the inner-map
	// template before the spec is consumed by loadFileopenObjects. The
	// per-container LPM tries are created from this template at
	// Watch() time.
	spec, err := loadFileopen()
	if err != nil {
		return nil, fmt.Errorf("loadFileopen: %w", err)
	}
	outerSpec, ok := spec.Maps["intended_sets"]
	if !ok || outerSpec.InnerMap == nil {
		return nil, fmt.Errorf("intended_sets outer map has no InnerMap spec; bpf2go layout changed?")
	}
	innerSpec := outerSpec.InnerMap.Copy()

	var objs fileopenObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("LoadAndAssign(fileopen): %w", err)
	}

	lsm, err := link.AttachLSM(link.LSMOptions{Program: objs.PsvFileOpen})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("AttachLSM(file_open): %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		lsm.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &FileOpen{
		objs:      objs,
		innerSpec: innerSpec,
		link:      lsm,
		reader:    rd,
		rawSize:   binary.Size(FileOpenEvent{}),
		inners:    map[uint32]*ebpf.Map{},
	}, nil
}

// Watch starts watching `cgroupID` and associates it with the given
// IntendedSet entries. A fresh inner LPM trie is created, populated
// from `entries`, and registered in the outer ARRAY_OF_MAPS at a
// freshly-allocated container_handle. The handle is also written to
// the watched_cgroups map so the probe can route from cgroup-id to
// trie at lookup time.
//
// Returns the container_handle assigned to this watched cgroup (mainly
// useful for tests and debugging; the probe does not surface it
// elsewhere). Adding an already-watched cgroup ID is currently a
// duplicate-add error — slice 23 may refine this to no-op-update once
// the higher-level Watcher owns container lifecycle.
func (f *FileOpen) Watch(cgroupID uint64, entries []IntendedSetEntry) (uint32, error) {
	f.innerMu.Lock()
	defer f.innerMu.Unlock()

	if f.nextHandle >= 4096 {
		return 0, fmt.Errorf("watched-container limit (4096) reached")
	}
	handle := f.nextHandle

	// 1. Build the inner LPM trie from the template spec captured at
	// NewFileOpen time. We Copy() the spec per call so each inner is
	// an independent kernel object.
	inner, err := ebpf.NewMap(f.innerSpec.Copy())
	if err != nil {
		return 0, fmt.Errorf("create inner LPM trie: %w", err)
	}
	// 2. Populate it.
	if err := populateIntendedSetMap(inner, entries); err != nil {
		inner.Close()
		return 0, err
	}
	// 3. Register it in the outer array. The Map.Put with an *ebpf.Map
	// value translates to the kernel-side fd registration.
	if err := f.objs.IntendedSets.Put(&handle, inner); err != nil {
		inner.Close()
		return 0, fmt.Errorf("register inner in outer ARRAY_OF_MAPS at handle %d: %w", handle, err)
	}
	// 4. Wire the cgroup → handle mapping the probe consults first.
	if err := f.objs.WatchedCgroups.Put(&cgroupID, &handle); err != nil {
		// Best-effort rollback of step 3; ignore errors there since
		// the user's error message about step 4 is the one that
		// matters.
		_ = f.objs.IntendedSets.Delete(&handle)
		inner.Close()
		return 0, fmt.Errorf("register cgroup %d → handle %d in watched_cgroups: %w", cgroupID, handle, err)
	}

	f.inners[handle] = inner
	f.nextHandle++
	return handle, nil
}

// Unwatch removes a cgroup from the watched set, deregisters its inner
// LPM trie from the outer array, and frees the inner map. Idempotent:
// removing an absent cgroup is a no-op; calling on a never-watched
// cgroup_id is also a no-op.
func (f *FileOpen) Unwatch(cgroupID uint64) error {
	f.innerMu.Lock()
	defer f.innerMu.Unlock()

	var handle uint32
	if err := f.objs.WatchedCgroups.Lookup(&cgroupID, &handle); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("lookup cgroup %d: %w", cgroupID, err)
	}

	if err := f.objs.WatchedCgroups.Delete(&cgroupID); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("unwatch cgroup %d: %w", cgroupID, err)
	}

	// Deregister from the outer array. Even if this fails, the inner
	// won't receive new lookups because the cgroup → handle mapping
	// is gone.
	if err := f.objs.IntendedSets.Delete(&handle); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("deregister inner at handle %d: %w", handle, err)
	}

	if inner, ok := f.inners[handle]; ok {
		_ = inner.Close()
		delete(f.inners, handle)
	}
	return nil
}

// Read blocks until the next event arrives or the reader is closed.
// Returns io.EOF after Close.
func (f *FileOpen) Read() (FileOpenEvent, error) {
	var ev FileOpenEvent
	record, err := f.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ev, io.EOF
		}
		return ev, fmt.Errorf("ringbuf.Read: %w", err)
	}
	if len(record.RawSample) < f.rawSize {
		return ev, fmt.Errorf("short ringbuf record: %d < %d", len(record.RawSample), f.rawSize)
	}
	if err := binary.Read(byteReader(record.RawSample[:f.rawSize]), nativeEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode event: %w", err)
	}
	return ev, nil
}

// Close detaches the probe, frees all inner maps, and releases the
// ringbuf reader. Safe to call multiple times; subsequent calls are
// no-ops.
func (f *FileOpen) Close() error {
	var errs []error

	if f.reader != nil {
		if err := f.reader.Close(); err != nil {
			errs = append(errs, err)
		}
		f.reader = nil
	}
	if f.link != nil {
		if err := f.link.Close(); err != nil {
			errs = append(errs, err)
		}
		f.link = nil
	}

	f.innerMu.Lock()
	for h, inner := range f.inners {
		if err := inner.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close inner handle %d: %w", h, err))
		}
	}
	f.inners = map[uint32]*ebpf.Map{}
	f.innerMu.Unlock()

	if err := f.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("close: %v", errs)
	}
	return nil
}
