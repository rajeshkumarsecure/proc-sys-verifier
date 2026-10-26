// Package render formats a diff.Report for human or machine consumption.
//
// JSON is the source of truth — stable, machine-friendly, what dashboards and
// aggregators see. TTY is the demo-ready human view: deviations grouped by
// class, each with a one-line "what to do" hint and the policy rule (if any)
// that surfaced or annotated it.
//
// The renderer is pure: it does not touch the filesystem and has no
// side effects beyond writing to the supplied io.Writer.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

// Format selects the output format for a Report. Add new formats here.
type Format string

const (
	FormatJSON Format = "json"
	FormatTTY  Format = "tty"
)

// ParseFormat resolves a string flag value into a Format. Returns an error
// for unknown values so the CLI surfaces a useful diagnostic.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "json", "JSON":
		return FormatJSON, nil
	case "tty", "TTY", "text":
		return FormatTTY, nil
	default:
		return "", fmt.Errorf("unknown format %q (expected: json, tty)", s)
	}
}

// Options controls renderer behavior. Zero value is safe: color defaults
// off (JSON never colors; TTY honors it when set).
type Options struct {
	Format Format
	Color  bool
}

// Render writes the report to w in the requested format.
func Render(w io.Writer, r diff.Report, opt Options) error {
	switch opt.Format {
	case "", FormatJSON:
		return renderJSON(w, r)
	case FormatTTY:
		return renderTTY(w, r, opt.Color)
	default:
		return fmt.Errorf("render: unknown format %q", opt.Format)
	}
}

func renderJSON(w io.Writer, r diff.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ansi color codes. Used only when Options.Color is true.
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiRed   = "\x1b[31m"
	ansiYel   = "\x1b[33m"
	ansiCyan  = "\x1b[36m"
	ansiGreen = "\x1b[32m"
)

// classMeta carries the human-facing presentation of each deviation class:
// a short label, a one-line fix hint, and a color.
type classMeta struct {
	label string
	hint  string
	color string
}

var classMetaTable = map[diff.Class]classMeta{
	diff.ClassWritableDrift: {
		label: "WRITABLE DRIFT",
		hint:  "path was supposed to be masked or read-only but is writable inside the container.",
		color: ansiRed,
	},
	diff.ClassOutOfPolicyRedirect: {
		label: "OUT-OF-POLICY REDIRECT",
		hint:  "a symlink's resolved target lands on a path the operator declared masked.",
		color: ansiYel,
	},
	diff.ClassCgroupDelegationExposure: {
		label: "CGROUP DELEGATION EXPOSURE",
		hint:  "a writable /sys/fs/cgroup file would reach outside the container's delegated subtree.",
		color: ansiRed,
	},
	diff.ClassPostStartRemount: {
		label: "POST-START REMOUNT",
		hint:  "a mount appeared after container start; eBPF watcher caught it under /proc or /sys.",
		color: ansiCyan,
	},
	diff.ClassRuntimeWrite: {
		label: "RUNTIME WRITE",
		hint:  "a write-open hit a path the OCI spec declared masked or read-only; eBPF watcher caught it in real time.",
		color: ansiRed,
	},
}

func renderTTY(w io.Writer, r diff.Report, color bool) error {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + ansiReset
	}

	// Header
	header := fmt.Sprintf("container %s  (init pid %d)", short(r.ContainerID), r.InitPID)
	if _, err := fmt.Fprintln(w, c(ansiBold, header)); err != nil {
		return err
	}

	if len(r.Deviations) == 0 && len(r.Annotations) == 0 {
		_, err := fmt.Fprintln(w, c(ansiGreen, "  no deviations — contract intact."))
		return err
	}
	if len(r.Deviations) == 0 {
		// Annotations only — still a clean baseline, just call it out and
		// fall through to print them under "context".
		if _, err := fmt.Fprintln(w, c(ansiGreen, "  no deviations — contract intact.")); err != nil {
			return err
		}
	}

	// Group by class, preserving differ's sorted order within each group.
	groups := groupByClass(r.Deviations)
	classes := sortedClasses(groups)

	for _, cls := range classes {
		meta, ok := classMetaTable[cls]
		if !ok {
			meta = classMeta{label: string(cls), hint: "(no description registered)", color: ansiRed}
		}
		count := len(groups[cls])
		head := fmt.Sprintf("\n%s  (%d)", meta.label, count)
		if _, err := fmt.Fprintln(w, c(meta.color, head)); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, c(ansiDim, "  "+meta.hint)); err != nil {
			return err
		}
		for _, d := range groups[cls] {
			line := "  " + d.Path
			if d.Rule != "" {
				line += "  " + c(ansiDim, "["+d.Rule+"]")
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
	}

	// Info-level annotations: dim block at the end so the eye reads
	// "deviations first, context second."
	if len(r.Annotations) > 0 {
		if _, err := fmt.Fprintln(w, c(ansiDim, fmt.Sprintf("\nCONTEXT  (%d)", len(r.Annotations)))); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, c(ansiDim, "  safe-but-noteworthy: the verifier understands these setups and is not flagging them.")); err != nil {
			return err
		}
		for _, a := range r.Annotations {
			line := fmt.Sprintf("  [%s] %s — %s", a.Kind, a.Path, a.Message)
			if _, err := fmt.Fprintln(w, c(ansiDim, line)); err != nil {
				return err
			}
		}
	}

	// Footer summary.
	if len(r.Deviations) > 0 {
		footer := fmt.Sprintf("\n%d deviation(s) total", len(r.Deviations))
		if _, err := fmt.Fprintln(w, c(ansiBold, footer)); err != nil {
			return err
		}
	}
	return nil
}

func groupByClass(devs []diff.Deviation) map[diff.Class][]diff.Deviation {
	out := map[diff.Class][]diff.Deviation{}
	for _, d := range devs {
		out[d.Class] = append(out[d.Class], d)
	}
	return out
}

func sortedClasses(groups map[diff.Class][]diff.Deviation) []diff.Class {
	out := make([]diff.Class, 0, len(groups))
	for c := range groups {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// short truncates a long container ID for compact TTY display, keeping it
// readable while still identifying.
func short(id string) string {
	const n = 12
	if len(id) <= n {
		return id
	}
	return id[:n]
}
