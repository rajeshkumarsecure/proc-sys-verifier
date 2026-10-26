// watcher.go — slice 23. High-level Watcher that owns both the
// sb_mount probe (PostStartRemount events) and the file_open probe
// (RuntimeWrite events) for a set of watched containers.
//
// The two probes are independent BPF programs with independent
// ringbufs; the Watcher fans out their events through a single
// channel and handles graceful shutdown so callers (psv watch,
// future psv DaemonSet) don't have to coordinate.
//
// Lifecycle:
//   w, err := watch.Open()        // attaches both probes
//   defer w.Close()
//   w.Add(container, intended)    // register cgroup + IntendedSet in both probes
//   for ev := range w.Events() {  // consumes deviations
//       ... // emit JSONL, sort into a Report, etc.
//   }
//
// The Events channel closes when w.Close() is called or when a
// fatal read error occurs on either ringbuf. Either way the channel
// closing is the caller's signal to exit cleanly.

package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
)

// Event is one Deviation observed at runtime, tagged with the
// container it came from so the consumer can route or annotate.
// The Deviation itself carries the class, path, observed payload,
// and intended class — same shape as static-scan Deviations.
type Event struct {
	ContainerID string
	Deviation   diff.Deviation
}

// Watcher fans events from both probes into a single channel.
// Safe for concurrent Add/Remove from one goroutine alongside a
// single Events consumer; not safe for concurrent Add/Remove calls.
type Watcher struct {
	sb *SBMount
	fo *FileOpen

	events chan Event
	errs   chan error // surfaced to caller via Err() after channel close

	mu      sync.Mutex
	tracked map[uint64]string // cgroup ID -> container ID, for event tagging

	wg     sync.WaitGroup
	cancel context.CancelFunc
	closed bool
}

// Open attaches both LSM probes and starts the per-probe reader
// goroutines. Returns ErrBPFLSMNotEnabled if `bpf` is not on the
// kernel's active LSM list. Callers must Close to release kernel
// resources.
func Open() (*Watcher, error) {
	sb, err := NewSBMount(nil)
	if err != nil {
		return nil, fmt.Errorf("attach sb_mount: %w", err)
	}
	fo, err := NewFileOpen()
	if err != nil {
		sb.Close()
		return nil, fmt.Errorf("attach file_open: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		sb:      sb,
		fo:      fo,
		events:  make(chan Event, 64),
		errs:    make(chan error, 2),
		tracked: map[uint64]string{},
		cancel:  cancel,
	}

	w.wg.Add(2)
	go w.runSBMount(ctx)
	go w.runFileOpen(ctx)

	return w, nil
}

// Add registers a container in both probes. `obs` provides the
// container's cgroup identity; `intended` provides the per-container
// LPM trie content for file_open.
//
// Returns the kernel cgroup ID for diagnostic purposes (callers
// usually just log it). Adding a container that's already tracked
// is a no-op for the cgroup map but produces a new file_open
// handle slot (slice 23 limitation; slice 24 may consolidate when
// the higher-level Watcher takes over both probes' lifecycle).
func (w *Watcher) Add(container observe.ObservedSet, intended *spec.IntendedSet) (uint64, error) {
	cgid, err := CgroupIDFromObservedPath(container.Cgroup.Path)
	if err != nil {
		return 0, fmt.Errorf("resolve cgroup id from %q: %w", container.Cgroup.Path, err)
	}

	if err := w.sb.Watch(cgid); err != nil {
		return cgid, fmt.Errorf("sb_mount.Watch: %w", err)
	}
	entries := IntendedSetEntries(intended)
	if _, err := w.fo.Watch(cgid, entries); err != nil {
		// Best-effort rollback: remove from sb_mount so the two
		// probes stay consistent. If this rollback itself fails we
		// log via err wrap; the caller's Close() will eventually
		// clean everything up.
		if errUnw := w.sb.Unwatch(cgid); errUnw != nil {
			err = fmt.Errorf("%w (and sb_mount rollback failed: %v)", err, errUnw)
		}
		return cgid, fmt.Errorf("file_open.Watch: %w", err)
	}

	w.mu.Lock()
	w.tracked[cgid] = container.ContainerID
	w.mu.Unlock()
	return cgid, nil
}

// Remove deregisters a cgroup from both probes. Idempotent; missing
// entries are silently OK so reload loops don't have to track state.
func (w *Watcher) Remove(cgid uint64) error {
	var errs []error
	if err := w.sb.Unwatch(cgid); err != nil {
		errs = append(errs, fmt.Errorf("sb_mount: %w", err))
	}
	if err := w.fo.Unwatch(cgid); err != nil {
		errs = append(errs, fmt.Errorf("file_open: %w", err))
	}
	w.mu.Lock()
	delete(w.tracked, cgid)
	w.mu.Unlock()
	if len(errs) > 0 {
		return fmt.Errorf("remove cgroup %d: %v", cgid, errs)
	}
	return nil
}

// Events returns the receive end of the fan-in channel. Closed
// after Close, or after both probes hit io.EOF.
func (w *Watcher) Events() <-chan Event { return w.events }

// Close detaches both probes, frees per-container maps, and waits
// for the reader goroutines to exit. Safe to call multiple times;
// subsequent calls are no-ops.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()

	w.cancel()
	var errs []error
	if err := w.sb.Close(); err != nil {
		errs = append(errs, fmt.Errorf("sb_mount.Close: %w", err))
	}
	if err := w.fo.Close(); err != nil {
		errs = append(errs, fmt.Errorf("file_open.Close: %w", err))
	}
	w.wg.Wait()
	close(w.events)
	close(w.errs)
	if len(errs) > 0 {
		return fmt.Errorf("close: %v", errs)
	}
	return nil
}

// Err drains any reader-goroutine errors that surfaced after Close.
// Returns nil if all readers exited cleanly (io.EOF) or if Close
// hasn't been called yet.
func (w *Watcher) Err() error {
	var errs []error
	for err := range w.errs {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("reader errors: %v", errs)
}

// containerIDFor returns the container ID associated with `cgid`,
// or the stringified cgroup ID if we don't have a mapping (shouldn't
// happen, but defensive — an in-flight event for a just-Removed
// cgroup would otherwise lose its tag).
func (w *Watcher) containerIDFor(cgid uint64) string {
	w.mu.Lock()
	id, ok := w.tracked[cgid]
	w.mu.Unlock()
	if !ok {
		return fmt.Sprintf("cgroup:%d", cgid)
	}
	return id
}

func (w *Watcher) runSBMount(ctx context.Context) {
	defer w.wg.Done()
	for {
		ev, err := w.sb.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				select {
				case w.errs <- fmt.Errorf("sb_mount.Read: %w", err):
				default:
				}
			}
			return
		}
		dev := SBMountToDeviation(ev)
		select {
		case w.events <- Event{ContainerID: w.containerIDFor(ev.CgroupID), Deviation: dev}:
		case <-ctx.Done():
			return
		}
	}
}

func (w *Watcher) runFileOpen(ctx context.Context) {
	defer w.wg.Done()
	for {
		ev, err := w.fo.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				select {
				case w.errs <- fmt.Errorf("file_open.Read: %w", err):
				default:
				}
			}
			return
		}
		dev := FileOpenToDeviation(ev)
		select {
		case w.events <- Event{ContainerID: w.containerIDFor(ev.CgroupID), Deviation: dev}:
		case <-ctx.Done():
			return
		}
	}
}
