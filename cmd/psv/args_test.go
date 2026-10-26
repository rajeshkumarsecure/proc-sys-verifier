package main

import (
	"flag"
	"reflect"
	"testing"
)

// makeFS builds a FlagSet whose flag mix mirrors what real subcommands
// declare: a couple of value-takers (string, duration) and a couple of
// booleans. The classification rules in splitFlagsAndPositionals depend
// on consulting this FlagSet to decide whether a -foo token consumes
// the next token as a value.
func makeFS() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("output", "", "")
	fs.String("policy", "default", "")
	fs.Bool("quiet", false, "")
	fs.Bool("no-color", false, "")
	return fs
}

func TestSplitFlagsAndPositionals(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantFlags   []string
		wantPosArgs []string
	}{
		{
			// Operator types the natural docker/kubectl order: positional
			// first, then flag. This is the bug-trigger that motivated
			// the helper.
			name:        "positional_then_flag",
			args:        []string{"sloppy", "-output", "/tmp/x.jsonl"},
			wantFlags:   []string{"-output", "/tmp/x.jsonl"},
			wantPosArgs: []string{"sloppy"},
		},
		{
			// The stdlib-friendly order still works unchanged.
			name:        "flag_then_positional",
			args:        []string{"-output", "/tmp/x.jsonl", "sloppy"},
			wantFlags:   []string{"-output", "/tmp/x.jsonl"},
			wantPosArgs: []string{"sloppy"},
		},
		{
			// Boolean flags must NOT consume the next token. Without
			// the isBoolFlag check, "demo" would be eaten as -quiet's
			// value and fs.Parse would error.
			name:        "boolean_flag_does_not_eat_next_token",
			args:        []string{"-quiet", "demo"},
			wantFlags:   []string{"-quiet"},
			wantPosArgs: []string{"demo"},
		},
		{
			// Mixed: positional, value-flag, positional, bool-flag.
			// Real-world shape an operator might type when re-running
			// with a tweak.
			name:        "mixed_order_full_round_trip",
			args:        []string{"sloppy", "-output", "/tmp/x.jsonl", "extra", "-quiet"},
			wantFlags:   []string{"-output", "/tmp/x.jsonl", "-quiet"},
			wantPosArgs: []string{"sloppy", "extra"},
		},
		{
			// Attached-value form (-foo=bar) is one token; no peek needed.
			name:        "attached_value_form",
			args:        []string{"sloppy", "-output=/tmp/x.jsonl"},
			wantFlags:   []string{"-output=/tmp/x.jsonl"},
			wantPosArgs: []string{"sloppy"},
		},
		{
			// Double-dash form (--output) is also recognized by the
			// stdlib flag package and our HasPrefix("-") check.
			name:        "double_dash_form",
			args:        []string{"sloppy", "--output", "/tmp/x.jsonl"},
			wantFlags:   []string{"--output", "/tmp/x.jsonl"},
			wantPosArgs: []string{"sloppy"},
		},
		{
			// Unknown flag with detached-style argument. We must NOT
			// peek the next token because we don't know if the unknown
			// flag is boolean. fs.Parse will reject it cleanly, which
			// is exactly the behavior the operator wants.
			name:        "unknown_flag_preserves_next_token_as_positional",
			args:        []string{"sloppy", "-unknown", "value"},
			wantFlags:   []string{"-unknown"},
			wantPosArgs: []string{"sloppy", "value"},
		},
		{
			// Bare "-" stays as a positional (used for "read from stdin"
			// in many CLIs; not used by psv today but we shouldn't trap it).
			name:        "bare_dash_is_positional",
			args:        []string{"-"},
			wantFlags:   nil,
			wantPosArgs: []string{"-"},
		},
		{
			// No args at all — neither slice is grown.
			name:        "empty",
			args:        nil,
			wantFlags:   nil,
			wantPosArgs: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := makeFS()
			gotF, gotP := splitFlagsAndPositionals(fs, tc.args)
			if !reflect.DeepEqual(gotF, tc.wantFlags) {
				t.Errorf("flags = %v, want %v", gotF, tc.wantFlags)
			}
			if !reflect.DeepEqual(gotP, tc.wantPosArgs) {
				t.Errorf("positionals = %v, want %v", gotP, tc.wantPosArgs)
			}
		})
	}
}

// End-to-end: parseFlagsAnywhere actually parses the reordered args
// such that fs.String("output", ...) ends up populated AND fs.Args()
// returns the positional. This is the contract every caller depends on.
func TestParseFlagsAnywhere_EndToEnd(t *testing.T) {
	fs := makeFS()
	output := fs.Lookup("output").Value
	quiet := fs.Lookup("quiet").Value

	// The exact invocation that prompted this fix.
	if err := parseFlagsAnywhere(fs, []string{"sloppy", "-output", "/tmp/x.jsonl", "-quiet"}); err != nil {
		t.Fatalf("parseFlagsAnywhere: %v", err)
	}
	if output.String() != "/tmp/x.jsonl" {
		t.Errorf("-output = %q, want /tmp/x.jsonl", output.String())
	}
	if quiet.String() != "true" {
		t.Errorf("-quiet = %q, want true", quiet.String())
	}
	if fs.NArg() != 1 || fs.Arg(0) != "sloppy" {
		t.Errorf("positionals = %v, want [sloppy]", fs.Args())
	}
}
