// ingest.go — slice 23. `psv scan -ingest <jsonl>` reads watch events
// produced by `psv watch -output FILE` and folds them into the static
// scan Report. The result is one Report covering the container's
// entire lifetime: what the spec said, what the static scan saw, and
// what the watcher caught in between.
//
// The merge contract:
//   - Watch events whose container_id matches the scanned container
//     are appended to Deviations.
//   - Events for OTHER containers are skipped silently (a single
//     events.jsonl can carry multiple containers' events if the
//     operator merged streams).
//   - Sort is stable on (Class, Path) — watch events fall in next to
//     their static-scan peers of the same class, which is what the
//     renderer's grouping expects.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

// ingestWatchEvents reads JSONL watch events from `path`, keeps the
// ones tagged with `containerID`, and returns them as Deviations
// ready to merge into a Report.
func ingestWatchEvents(path, containerID string) ([]diff.Deviation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ingest file: %w", err)
	}
	defer f.Close()
	return decodeWatchEvents(f, containerID)
}

// decodeWatchEvents is the I/O-agnostic core, separated so tests can
// drive it with a bytes.Buffer.
func decodeWatchEvents(r io.Reader, containerID string) ([]diff.Deviation, error) {
	// We decode each line independently — bufio.Scanner with a
	// generous buffer handles the "long target path" case without
	// pulling in a streaming decoder.
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var devs []diff.Deviation
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Decode into a structurally-typed envelope first so we can
		// route by container_id before doing the per-class typed
		// decode for the Deviation payload.
		var env struct {
			ContainerID string          `json:"container_id"`
			Deviation   json.RawMessage `json:"deviation"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, fmt.Errorf("line %d: decode envelope: %w", lineNo, err)
		}
		if env.ContainerID != containerID {
			continue
		}
		// Two-phase decode for the Deviation: peek at Class to know
		// which typed Observed/Intended payload to unmarshal into.
		// This mirrors the scheme the differ uses on the way out;
		// the watch -> scan round-trip preserves type fidelity.
		var head struct {
			Class diff.Class `json:"class"`
		}
		if err := json.Unmarshal(env.Deviation, &head); err != nil {
			return nil, fmt.Errorf("line %d: decode class: %w", lineNo, err)
		}
		dev, err := decodeDeviationByClass(env.Deviation, head.Class)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		devs = append(devs, dev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ingest file: %w", err)
	}
	return devs, nil
}

// decodeDeviationByClass dispatches the typed-payload decode for one
// Deviation. Unknown classes fall through with raw json.RawMessage
// payloads so the ingest tolerates future watch event types without
// being a forward-compat blocker for older psv binaries.
func decodeDeviationByClass(raw []byte, class diff.Class) (diff.Deviation, error) {
	switch class {
	case diff.ClassPostStartRemount:
		var d struct {
			Class    diff.Class                    `json:"class"`
			Path     string                        `json:"path"`
			Observed diff.PostStartRemountObserved `json:"observed"`
			Intended diff.PostStartRemountIntended `json:"intended"`
			Rule     string                        `json:"rule,omitempty"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return diff.Deviation{}, fmt.Errorf("decode PostStartRemount: %w", err)
		}
		return diff.Deviation{
			Class: d.Class, Path: d.Path, Observed: d.Observed, Intended: d.Intended, Rule: d.Rule,
		}, nil
	case diff.ClassRuntimeWrite:
		var d struct {
			Class    diff.Class                `json:"class"`
			Path     string                    `json:"path"`
			Observed diff.RuntimeWriteObserved `json:"observed"`
			Intended diff.RuntimeWriteIntended `json:"intended"`
			Rule     string                    `json:"rule,omitempty"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return diff.Deviation{}, fmt.Errorf("decode RuntimeWrite: %w", err)
		}
		return diff.Deviation{
			Class: d.Class, Path: d.Path, Observed: d.Observed, Intended: d.Intended, Rule: d.Rule,
		}, nil
	default:
		// Forward-compatible fallback: keep the raw observed/intended
		// JSON. Renderers that don't recognize the class will display
		// it with the "(no description registered)" fallback.
		var d struct {
			Class    diff.Class      `json:"class"`
			Path     string          `json:"path"`
			Observed json.RawMessage `json:"observed"`
			Intended json.RawMessage `json:"intended"`
			Rule     string          `json:"rule,omitempty"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return diff.Deviation{}, fmt.Errorf("decode unknown class %q: %w", class, err)
		}
		return diff.Deviation{
			Class: d.Class, Path: d.Path, Observed: d.Observed, Intended: d.Intended, Rule: d.Rule,
		}, nil
	}
}

// mergeWatchDeviations appends `extras` to `base` and re-sorts the
// combined list by (Class, Path). Stable sort so events with the same
// (class, path) preserve their input order — which for watch events
// means chronological order.
func mergeWatchDeviations(base, extras []diff.Deviation) []diff.Deviation {
	if len(extras) == 0 {
		return base
	}
	out := make([]diff.Deviation, 0, len(base)+len(extras))
	out = append(out, base...)
	out = append(out, extras...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].Path < out[j].Path
	})
	return out
}
