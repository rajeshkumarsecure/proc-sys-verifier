// args.go — small helper that lets every subcommand accept flags
// *after* positional arguments, matching the docker / kubectl / git
// convention. Go's stdlib `flag` package stops parsing at the first
// non-flag token, which surprises operators every time:
//
//   bin/psv watch sloppy -output /tmp/x.jsonl   # flag stops at "sloppy"
//   bin/psv watch -output /tmp/x.jsonl sloppy   # parses fine
//
// The fix is mechanical: reorder args into [flags...] then [positionals...]
// before calling fs.Parse. We do it once here so every subcommand picks
// it up by swapping `fs.Parse(args)` for `parseFlagsAnywhere(fs, args)`.

package main

import (
	"flag"
	"strings"
)

// parseFlagsAnywhere is a drop-in replacement for fs.Parse(args) that
// tolerates flags interleaved with positional arguments. It reshuffles
// args so flags appear first (preserving their order, and their
// optional value when given as `-flag value` rather than `-flag=value`),
// then hands the result to fs.Parse.
//
// It does NOT support the GNU `--` separator as a "stop processing
// flags" terminator, because none of our subcommands take literal
// arguments that begin with `-`. If that changes, this helper grows
// a `--` branch that copies the tail verbatim to the positional list.
func parseFlagsAnywhere(fs *flag.FlagSet, args []string) error {
	flags, positionals := splitFlagsAndPositionals(fs, args)
	// fs.Parse expects [flags..., positionals...]. After Parse, fs.Args()
	// returns the positionals — same shape as if the operator had typed
	// them in flag-first order.
	reordered := append(flags, positionals...)
	return fs.Parse(reordered)
}

// splitFlagsAndPositionals walks `args` left-to-right and classifies
// each token. Returns (flags, positionals) where each preserves its
// input order. Exported for testing.
//
// Classification rules (matching the stdlib flag package's grammar):
//
//	-foo            boolean flag, OR string flag whose value follows
//	-foo=bar        flag with attached value (one token)
//	-foo bar        flag with detached value (two tokens) — only when foo is non-boolean
//	bar             positional
//
// We consult the FlagSet to tell boolean from value-taking flags so we
// don't accidentally consume the next token as a boolean flag's value.
func splitFlagsAndPositionals(fs *flag.FlagSet, args []string) (flags, positionals []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		// "-" and "" are positional by convention.
		if a == "-" || a == "" {
			positionals = append(positionals, a)
			continue
		}
		if !strings.HasPrefix(a, "-") {
			positionals = append(positionals, a)
			continue
		}

		flags = append(flags, a)
		// Attached-value form (-foo=bar) is one token; nothing more
		// to consume.
		if strings.Contains(a, "=") {
			continue
		}
		// Detached-value form: peek at the FlagSet to decide whether
		// the next token is this flag's value.
		name := strings.TrimLeft(a, "-")
		f := fs.Lookup(name)
		if f == nil {
			// Unknown flag — let fs.Parse surface the error rather
			// than consume an extra token we shouldn't.
			continue
		}
		if isBoolFlag(f) {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return flags, positionals
}

// isBoolFlag reports whether f's underlying Value implements the
// stdlib's boolFlag interface (which `flag.Bool` does). Boolean flags
// never consume a following token.
func isBoolFlag(f *flag.Flag) bool {
	type boolFlag interface{ IsBoolFlag() bool }
	bf, ok := f.Value.(boolFlag)
	return ok && bf.IsBoolFlag()
}
