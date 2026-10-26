// watch_cmd.go — slice 23. `psv watch <container>` attaches the eBPF
// probes (sb_mount + file_open) to the named container and streams
// runtime deviations to stdout or a file as JSONL. Blocks until
// SIGINT/SIGTERM or the container exits.
//
// The output format intentionally differs from `psv scan`: scan
// produces one JSON Report object; watch produces one Deviation per
// line (JSONL), wrapped in a small envelope that carries the
// container ID. That makes the output streamable, line-tail-friendly,
// and trivially mergeable into a static Report via `psv scan -ingest`.
//
// Wire envelope:
//   {
//     "container_id": "demo",
//     "deviation":    { ... diff.Deviation ... }
//   }
//
// Slice 23 keeps the policy filter out of `psv watch` on purpose:
// the watcher emits raw events, and `psv scan -ingest` applies the
// policy at ingest time. That way an operator can watch once and
// later experiment with different profiles without re-running the
// watcher.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/discover"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/watch"
)

// WatchEnvelope is the JSONL line shape produced by `psv watch`. It
// is the input shape `psv scan -ingest` expects to read.
type WatchEnvelope struct {
	ContainerID string            `json:"container_id"`
	Deviation   any               `json:"deviation"` // diff.Deviation; kept as any so watch_cmd doesn't grow a diff import cycle in tests
	Source      string            `json:"source,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

func cmdWatch(args []string, stdout, stderr io.Writer, sources []discover.Source) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", 0, "max wall time to watch (0 = until SIGINT or container exit)")
	outputPath := fs.String("output", "", "write JSONL events to FILE instead of stdout")
	quiet := fs.Bool("quiet", false, "suppress the startup banner on stderr")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: psv watch [flags] <container-id>")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\nStreams runtime deviations as JSONL. One line per event:")
		fmt.Fprintln(stderr, `  {"container_id":"...","deviation":{...}}`)
		fmt.Fprintln(stderr, "\nRequires `bpf` in the kernel's active LSM list; see scripts/enable-bpf-lsm.sh.")
	}
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	want := fs.Arg(0)

	// 1. Discover the target container.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cs, discErr := discover.All(ctx, sources)
	if discErr != nil {
		fmt.Fprintf(stderr, "psv: discover: %v\n", discErr)
	}
	target := findContainer(cs, want)
	if target == nil {
		return reportNoMatch(stderr, want, discErr)
	}
	if target.SpecPath == "" {
		fmt.Fprintf(stderr, "psv: container %q has no known OCI spec path; cannot watch\n", target.ID)
		return 1
	}

	// 2. Load the spec + observe the container (we need IntendedSet
	// for the file_open LPM trie, and CgroupInfo to resolve the
	// kernel cgroup id).
	intended, err := spec.Load(target.SpecPath)
	if err != nil {
		fmt.Fprintf(stderr, "psv: load spec: %v\n", err)
		return 1
	}
	observed, err := observe.Container(ctx, *target)
	if err != nil {
		fmt.Fprintf(stderr, "psv: observe: %v\n", err)
		return 1
	}

	// 3. Attach the probes.
	w, err := watch.Open()
	if err != nil {
		fmt.Fprintf(stderr, "psv: open watcher: %v\n", err)
		return 1
	}
	defer w.Close()

	cgid, err := w.Add(*observed, intended)
	if err != nil {
		fmt.Fprintf(stderr, "psv: register container: %v\n", err)
		return 1
	}

	// 4. Open the output sink.
	out := stdout
	if *outputPath != "" {
		f, err := os.Create(*outputPath)
		if err != nil {
			fmt.Fprintf(stderr, "psv: open output: %v\n", err)
			return 1
		}
		defer f.Close()
		out = f
	}

	// 5. Banner (stderr so it doesn't contaminate the JSONL stream).
	if !*quiet {
		fmt.Fprintf(stderr, "psv watch: container=%s cgroup_id=%d intended_entries=%d\n",
			target.ID, cgid, len(observed.Cgroup.Path)) // entries count is in IntendedSet; observed.Cgroup.Path is just for traceable identity
		_ = intended // explicit reference for clarity; counts not pulled out to avoid widening the printf shape
		fmt.Fprintln(stderr, "psv watch: streaming events as JSONL; Ctrl-C to stop")
	}

	// 6. Signal-aware run loop. SIGINT/SIGTERM triggers graceful
	// shutdown: the deferred w.Close() detaches probes; the events
	// channel closes; the encoder loop drains pending events and
	// returns.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	deadlineCh := make(<-chan time.Time)
	if *timeout > 0 {
		t := time.NewTimer(*timeout)
		defer t.Stop()
		deadlineCh = t.C
	}

	enc := json.NewEncoder(out)
	for {
		select {
		case sig := <-sigCh:
			if !*quiet {
				fmt.Fprintf(stderr, "psv watch: caught %s; detaching\n", sig)
			}
			return 0
		case <-deadlineCh:
			if !*quiet {
				fmt.Fprintf(stderr, "psv watch: timeout (%s) reached; detaching\n", *timeout)
			}
			return 0
		case ev, ok := <-w.Events():
			if !ok {
				// Both probes EOF — clean exit.
				if !*quiet {
					fmt.Fprintln(stderr, "psv watch: event stream closed")
				}
				return 0
			}
			env := WatchEnvelope{
				ContainerID: ev.ContainerID,
				Deviation:   ev.Deviation,
				Source:      "watch",
			}
			if err := enc.Encode(env); err != nil {
				fmt.Fprintf(stderr, "psv watch: encode: %v\n", err)
				return 1
			}
		}
	}
}

// trimToFirstLine returns the first newline-delimited line of s, for
// stderr messages that should be one-liners. (Not used yet; kept for
// upcoming watch.Err() drain when we surface reader errors.)
func trimToFirstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
