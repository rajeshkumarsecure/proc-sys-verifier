// hello.go — slice 20 loader. Wraps the bpf2go-generated bindings in a
// small ergonomic API: NewHello -> Read -> Close. The shape mirrors
// what slices 21–23 will use for the real probes.

package watch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// HelloEvent mirrors struct psv_event in bpf/hello/hello.bpf.c. The C
// struct uses fixed-size integers and a 16-byte char array, all
// naturally aligned; the layout below is the exact wire format we
// decode from the ringbuf.
type HelloEvent struct {
	PID      uint32
	TGID     uint32
	CgroupID uint64
	Comm     [16]byte
}

// CommString returns the null-terminated comm field as a Go string.
// Kernel comm is always null-padded; the trim is a safety net.
func (e *HelloEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// Hello is an attached sched_process_exec probe with its ringbuf
// reader. Construct via NewHello; release via Close.
type Hello struct {
	objs    helloObjects
	link    link.Link
	reader  *ringbuf.Reader
	rawSize int
}

// NewHello loads the BPF object, attaches the tracepoint, and opens
// the ringbuf reader. Returns an error if any step fails; partial
// state is cleaned up before returning.
func NewHello() (*Hello, error) {
	// MEMLOCK rlimit is hit on pre-5.11 kernels and on hardened
	// configs even on modern ones. Lifting it is the canonical first
	// step of every cilium/ebpf loader; cheap and idempotent.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}

	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loadHelloObjects: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &Hello{
		objs:    objs,
		link:    tp,
		reader:  rd,
		rawSize: binary.Size(HelloEvent{}),
	}, nil
}

// Read blocks until the next event arrives or the reader is closed.
// Returns io.EOF when Close has been called.
func (h *Hello) Read() (HelloEvent, error) {
	var ev HelloEvent
	record, err := h.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ev, io.EOF
		}
		return ev, fmt.Errorf("ringbuf.Read: %w", err)
	}
	if len(record.RawSample) < h.rawSize {
		return ev, fmt.Errorf("short ringbuf record: %d < %d", len(record.RawSample), h.rawSize)
	}
	// The kernel and the verifier write events in native endianness
	// (cilium/ebpf compiles bpfel for little-endian targets), so
	// NativeEndian is correct here. Cross-compiled big-endian targets
	// pick up hello_bpfeb.go at build time.
	if err := binary.Read(byteReader(record.RawSample[:h.rawSize]), nativeEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode event: %w", err)
	}
	return ev, nil
}

// Close detaches the probe and frees kernel resources. Safe to call
// multiple times; subsequent calls are no-ops.
func (h *Hello) Close() error {
	var errs []error
	if h.reader != nil {
		if err := h.reader.Close(); err != nil {
			errs = append(errs, err)
		}
		h.reader = nil
	}
	if h.link != nil {
		if err := h.link.Close(); err != nil {
			errs = append(errs, err)
		}
		h.link = nil
	}
	if err := h.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("close: %v", errs)
	}
	return nil
}
