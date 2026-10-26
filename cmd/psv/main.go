// Command psv is the proc-sys-verifier CLI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/discover"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/observe"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/policy"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/render"
	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/spec"
)

// Build-time metadata. Override with:
//
//	go build -ldflags "-X main.version=v0.1.0 -X main.commit=abc1234 -X main.date=2026-05-29"
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `psv — proc-sys-verifier: check what containers actually see under /proc and /sys.

Usage:
  psv <command> [flags]

Commands:
  version        Print version, commit, and build date.
  list           List running containers discovered on this host.
  inspect-spec   Load an OCI config.json and print its IntendedSet as JSON.
  observe        Enter a container's namespaces and print its ObservedSet as JSON.
  scan           Diff a container's IntendedSet against its ObservedSet (JSON report).
  watch          Stream runtime deviations from the eBPF watcher as JSONL.
  help           Show this help message.

Run "psv <command> -h" for command-specific flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "-v", "--version":
		return cmdVersion(rest, stdout, stderr)
	case "list":
		return cmdList(rest, stdout, stderr, defaultSources())
	case "inspect-spec":
		return cmdInspectSpec(rest, stdout, stderr)
	case "observe":
		return cmdObserve(rest, stdout, stderr, defaultSources())
	case "scan":
		return cmdScan(rest, stdout, stderr, defaultSources())
	case "watch":
		return cmdWatch(rest, stdout, stderr, defaultSources())
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "psv: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	short := fs.Bool("short", false, "print only the version string")
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	if *short {
		fmt.Fprintln(stdout, version)
		return 0
	}
	fmt.Fprintf(stdout, "psv %s\n  commit: %s\n  built:  %s\n  go:     %s %s/%s\n",
		version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return 0
}

func cmdInspectSpec(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect-spec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: psv inspect-spec <path-to-config.json>")
		fs.PrintDefaults()
	}
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	set, err := spec.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "psv: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(set); err != nil {
		fmt.Fprintf(stderr, "psv: encode: %v\n", err)
		return 1
	}
	return 0
}

// defaultSources is the production set of container discovery sources, ordered
// from most-authoritative to least. Override in tests.
//
// We always include the default runc-root source. We additionally probe
// the well-known containerd runc-root paths:
//
//   - /run/containerd/runc/default   — `ctr run` and Kubernetes-via-CRI workloads
//   - /run/containerd/runc/moby      — Docker (moby project's containerd namespace)
//   - /run/containerd/runc/k8s.io    — k3s and other Kubernetes-via-containerd setups
//
// Each alternate source's Available() returns false when its root directory
// is absent, so this list is a no-op on hosts that don't run containerd or
// don't run Docker. Adding more known paths here later (CRI-O proxies,
// etc.) is purely additive.
func defaultSources() []discover.Source {
	return []discover.Source{
		discover.NewRuncSource(),
		&discover.RuncSource{Root: "/run/containerd/runc/default"},
		&discover.RuncSource{Root: "/run/containerd/runc/moby"},
		// Docker ships its own bundled containerd whose runc state lives
		// under /run/docker/runtime-runc/moby, not /run/containerd/runc/moby
		// (that path only applies when Docker is pointed at the system
		// containerd). Probe both so `psv` finds Docker containers on a
		// default Docker install.
		&discover.RuncSource{Root: "/run/docker/runtime-runc/moby"},
		&discover.RuncSource{Root: "/run/containerd/runc/k8s.io"},
	}
}

// geteuid is os.Geteuid via an indirection so tests can fake non-root runs.
var geteuid = os.Geteuid

// rootHint returns a one-line nudge for users who likely need sudo. Empty
// when running as root.
func rootHint() string {
	if geteuid() == 0 {
		return ""
	}
	return fmt.Sprintf("hint: psv usually needs root to read /proc/<pid>/ns and runtime state (euid=%d); try `sudo psv ...`", geteuid())
}

func cmdList(args []string, stdout, stderr io.Writer, sources []discover.Source) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit results as JSON instead of a table")
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}

	cs, discErr := discover.All(context.Background(), sources)
	if discErr != nil {
		// Non-fatal: print partial results, surface the error.
		fmt.Fprintf(stderr, "psv: discover: %v\n", discErr)
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cs); err != nil {
			fmt.Fprintf(stderr, "psv: encode: %v\n", err)
			return 1
		}
		return 0
	}

	if len(cs) == 0 {
		fmt.Fprintln(stdout, "no containers found")
		if h := rootHint(); h != "" {
			fmt.Fprintln(stderr, h)
		}
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tRUNTIME\tSTATUS\tPID\tBUNDLE")
	for _, c := range cs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n",
			truncateID(c.ID), c.Runtime, c.Status, c.InitPID, c.BundlePath)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "psv: flush: %v\n", err)
		return 1
	}
	return 0
}

func truncateID(id string) string {
	const n = 12
	if len(id) <= n {
		return id
	}
	return id[:n]
}

func cmdObserve(args []string, stdout, stderr io.Writer, sources []discover.Source) int {
	fs := flag.NewFlagSet("observe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", 30*time.Second, "max time to spend in the container's namespaces")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: psv observe <container-id>")
		fs.PrintDefaults()
	}
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	want := fs.Arg(0)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	cs, discErr := discover.All(ctx, sources)
	if discErr != nil {
		fmt.Fprintf(stderr, "psv: discover: %v\n", discErr)
	}
	var target *discover.Container
	for i := range cs {
		if cs[i].ID == want || (len(want) >= 4 && len(cs[i].ID) >= len(want) && cs[i].ID[:len(want)] == want) {
			target = &cs[i]
			break
		}
	}
	if target == nil {
		if discErr != nil {
			fmt.Fprintf(stderr, "psv: no container matches %q (discovery had errors above)\n", want)
		} else {
			fmt.Fprintf(stderr, "psv: no container matches %q\n", want)
		}
		if h := rootHint(); h != "" {
			fmt.Fprintln(stderr, h)
		}
		return 1
	}

	set, err := observe.Container(ctx, *target)
	if err != nil {
		fmt.Fprintf(stderr, "psv: observe: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(set); err != nil {
		fmt.Fprintf(stderr, "psv: encode: %v\n", err)
		return 1
	}
	return 0
}

// findContainer returns the entry in cs that matches `want`: either an exact
// ID match or a prefix match if `want` is at least 4 characters. Returns nil
// when nothing matches.
func findContainer(cs []discover.Container, want string) *discover.Container {
	for i := range cs {
		id := cs[i].ID
		if id == want {
			return &cs[i]
		}
		if len(want) >= 4 && len(id) >= len(want) && id[:len(want)] == want {
			return &cs[i]
		}
	}
	return nil
}

// reportNoMatch prints the standard "no container matches" diagnostic, with
// the discovery-error hint when applicable and the sudo hint for non-root.
func reportNoMatch(stderr io.Writer, want string, discErr error) int {
	if discErr != nil {
		fmt.Fprintf(stderr, "psv: no container matches %q (discovery had errors above)\n", want)
	} else {
		fmt.Fprintf(stderr, "psv: no container matches %q\n", want)
	}
	if h := rootHint(); h != "" {
		fmt.Fprintln(stderr, h)
	}
	return 1
}

func cmdScan(args []string, stdout, stderr io.Writer, sources []discover.Source) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", 30*time.Second, "max time to spend in the container's namespaces")
	profileName := fs.String("policy", "default", "built-in policy profile to apply ("+strings.Join(policy.BuiltinNames(), ", ")+")")
	profilePath := fs.String("policy-file", "", "path to a custom YAML profile (overrides -policy)")
	format := fs.String("format", "json", "output format: json | tty")
	noColor := fs.Bool("no-color", false, "disable ANSI color in tty output")
	ingestPath := fs.String("ingest", "", "merge watch events from FILE (JSONL from `psv watch -output`) into the scan report")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: psv scan [flags] <container-id>")
		fs.PrintDefaults()
	}
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	want := fs.Arg(0)

	renderFormat, err := render.ParseFormat(*format)
	if err != nil {
		fmt.Fprintf(stderr, "psv: %v\n", err)
		return 2
	}

	prof, err := loadPolicy(*profileName, *profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "psv: load policy: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
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
		fmt.Fprintf(stderr, "psv: container %q has no known OCI spec path; cannot scan\n", target.ID)
		return 1
	}

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

	res := diff.Diff(intended, observed)
	deviations := res.Deviations
	if *ingestPath != "" {
		watchDevs, err := ingestWatchEvents(*ingestPath, target.ID)
		if err != nil {
			fmt.Fprintf(stderr, "psv: ingest %s: %v\n", *ingestPath, err)
			return 1
		}
		deviations = mergeWatchDeviations(deviations, watchDevs)
	}
	report := diff.Report{
		ContainerID: target.ID,
		InitPID:     target.InitPID,
		Deviations:  policy.Apply(prof, deviations),
		Annotations: res.Annotations,
	}
	opt := render.Options{
		Format: renderFormat,
		Color:  renderFormat == render.FormatTTY && !*noColor && isTerminal(stdout),
	}
	if err := render.Render(stdout, report, opt); err != nil {
		fmt.Fprintf(stderr, "psv: render: %v\n", err)
		return 1
	}
	return 0
}

// isTerminal reports whether w is connected to a terminal. Used to decide
// whether to emit ANSI color by default. Tests pass *bytes.Buffer here,
// which is not a terminal, so color stays off in unit tests.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// loadPolicy resolves the --policy / --policy-file flags into a Profile.
// An explicit --policy-file overrides the built-in name. An empty name
// returns (nil, nil) so Apply treats it as a pass-through.
func loadPolicy(name, file string) (*policy.Profile, error) {
	if file != "" {
		return policy.LoadFile(file)
	}
	if name == "" {
		return nil, nil
	}
	return policy.Builtin(name)
}
