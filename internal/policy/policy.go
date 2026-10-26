// Package policy loads YAML policy profiles and applies them to a slice of
// deviations produced by the differ.
//
// A profile is a list of allow rules and a list of deny rules. Each rule
// targets a Class (WritableDrift, OutOfPolicyRedirect, …) and a path glob.
// Apply walks deviations once:
//
//   - If an allow rule matches, the deviation is dropped from the output
//     (suppressed because the operator deems it expected).
//   - If a deny rule matches, the deviation is kept and its Rule field is
//     set to the matching rule's Name (so the renderer can label it).
//   - If both match, deny wins. Explicit intent beats default allow.
//   - If neither matches, the deviation passes through unchanged.
//
// Profiles ship as YAML files under //policies and are embedded into the
// binary via go:embed in this package; no runtime file lookup is required.
package policy

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rajeshkumarsecure/proc-sys-verifier/internal/diff"
)

// Rule is a single allow or deny entry. Class, PathGlob, and Scope are all
// matched against incoming deviations; Reason is recorded with the rule for
// the renderer to surface. A rule must specify at least one of PathGlob or
// Scope; the loader rejects rules that specify neither.
type Rule struct {
	Class    diff.Class `yaml:"class"`
	PathGlob string     `yaml:"path_glob,omitempty"`
	Scope    Scope      `yaml:"scope,omitempty"`
	Reason   string     `yaml:"reason,omitempty"`
	// Name is set by the loader to "<rule-kind>:<index>:<glob-or-scope>" so
	// a matched rule has a stable, descriptive identifier in the report.
	Name string `yaml:"-"`
}

// Scope is an enum of semantic predicates that depend on per-deviation
// context the loader cannot evaluate. Today only the cgroup-delegation
// predicates exist; future scopes (host_root, pid_ns_shared, …) go here.
//
// An empty Scope means "any" and is the legacy single-axis behavior.
type Scope string

const (
	// ScopeDelegatedSubtree matches CgroupDelegationExposure deviations
	// whose EffectivePath lies inside the container's own delegated
	// subtree. Use to ALLOW writes systemd-in-container is expected to make.
	ScopeDelegatedSubtree Scope = "delegated_subtree"
	// ScopeAboveDelegatedRoot matches CgroupDelegationExposure deviations
	// whose EffectivePath escapes the delegated subtree. Use to DENY writes
	// that could affect parent or sibling cgroups.
	ScopeAboveDelegatedRoot Scope = "above_delegated_root"
)

// Profile is one loaded policy file.
type Profile struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Allow       []Rule `yaml:"allow"`
	Deny        []Rule `yaml:"deny"`
}

//go:embed all:builtin
var builtinFS embed.FS

// Load reads, parses, and validates a profile from r. The caller-supplied
// origin is used in error messages.
func Load(r io.Reader, origin string) (*Profile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", origin, err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", origin, err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("parse %s: profile missing required field 'name'", origin)
	}
	for i := range p.Allow {
		p.Allow[i].Name = ruleName("allow", i, p.Allow[i])
	}
	for i := range p.Deny {
		p.Deny[i].Name = ruleName("deny", i, p.Deny[i])
	}
	if err := validate(&p); err != nil {
		return nil, fmt.Errorf("validate %s: %w", origin, err)
	}
	return &p, nil
}

// ruleName builds the stable identifier the renderer shows when a rule
// matches. Prefers the glob; falls back to the scope when there is no glob.
func ruleName(kind string, i int, r Rule) string {
	label := r.PathGlob
	if label == "" {
		label = "scope=" + string(r.Scope)
	}
	return fmt.Sprintf("%s:%d:%s", kind, i, label)
}

// LoadFile is a convenience wrapper around Load for a path on disk.
func LoadFile(path string) (*Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f, path)
}

// Builtin returns one of the profiles shipped inside the binary by name
// (e.g. "default"). Returns an error if the profile does not exist.
func Builtin(name string) (*Profile, error) {
	f, err := builtinFS.Open("builtin/" + name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("builtin profile %q: %w", name, err)
	}
	defer f.Close()
	return Load(f, "builtin:"+name)
}

// BuiltinNames returns the list of profile names shipped inside the binary,
// sorted. Used by `psv --help`-adjacent listings.
func BuiltinNames() []string {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.TrimSuffix(e.Name(), ".yaml")
		if n == e.Name() {
			continue // not a YAML file
		}
		names = append(names, n)
	}
	return names
}

func validate(p *Profile) error {
	check := func(rules []Rule, kind string) error {
		for i, r := range rules {
			if r.PathGlob == "" && r.Scope == "" {
				return fmt.Errorf("%s rule %d: must specify path_glob or scope", kind, i)
			}
			if r.Scope != "" && !knownScope(r.Scope) {
				return fmt.Errorf("%s rule %d: unknown scope %q", kind, i, r.Scope)
			}
			if r.PathGlob == "" {
				continue
			}
			// Split on "**" and validate each segment via path.Match so a
			// truly malformed glob (e.g. unterminated `[`) still errors at
			// load time. path.Match treats `**` as two adjacent `*` which
			// it accepts, so validating the whole string is also fine.
			for _, seg := range strings.Split(r.PathGlob, "**") {
				if _, err := path.Match(seg, "/"); err != nil {
					return fmt.Errorf("%s rule %d: invalid path_glob %q: %w", kind, i, r.PathGlob, err)
				}
			}
		}
		return nil
	}
	if err := check(p.Allow, "allow"); err != nil {
		return err
	}
	return check(p.Deny, "deny")
}

// knownScope returns true for any Scope value the policy engine knows how
// to evaluate. Add new scopes here and in matchScope below.
func knownScope(s Scope) bool {
	switch s {
	case ScopeDelegatedSubtree, ScopeAboveDelegatedRoot:
		return true
	}
	return false
}

// Apply filters and annotates `devs` against `p`. Returns a new slice; the
// input is not mutated. A nil profile is a no-op (returns devs unchanged).
func Apply(p *Profile, devs []diff.Deviation) []diff.Deviation {
	if p == nil {
		return devs
	}
	out := make([]diff.Deviation, 0, len(devs))
	for _, d := range devs {
		// Deny is evaluated first so an explicit deny survives even when an
		// allow rule on a broader glob would otherwise have suppressed it.
		if denied := match(d, p.Deny); denied != nil {
			d.Rule = denied.Name
			out = append(out, d)
			continue
		}
		if match(d, p.Allow) != nil {
			continue
		}
		out = append(out, d)
	}
	return out
}

// match returns the first rule whose Class, PathGlob, and Scope all match
// d, or nil if none does. An empty Class matches any class. An empty
// PathGlob matches any path. An empty Scope matches any deviation.
func match(d diff.Deviation, rules []Rule) *Rule {
	for i := range rules {
		r := &rules[i]
		if r.Class != "" && r.Class != d.Class {
			continue
		}
		if r.PathGlob != "" && !globMatch(r.PathGlob, d.Path) {
			continue
		}
		if r.Scope != "" && !matchScope(r.Scope, d) {
			continue
		}
		return r
	}
	return nil
}

// matchScope evaluates a semantic scope predicate against a deviation.
// Today only the cgroup-delegation predicates exist; both read the
// CgroupDelegationExposureObserved payload. Other classes never satisfy
// these scopes, so a scope rule on a non-cgroup class is a silent no-op
// (deliberate: lets you write profiles that target the cgroup case without
// special-casing every WritableDrift rule above them).
func matchScope(s Scope, d diff.Deviation) bool {
	switch s {
	case ScopeDelegatedSubtree, ScopeAboveDelegatedRoot:
		obs, ok := d.Observed.(diff.CgroupDelegationExposureObserved)
		if !ok {
			return false
		}
		inside := isInsideCgroup(obs.EffectivePath, obs.ContainerCgroup)
		if s == ScopeDelegatedSubtree {
			return inside
		}
		return !inside
	}
	return false
}

// isInsideCgroup mirrors diff.isInside without importing the unexported
// helper. Both paths are cgroup paths (forward-slash, leading "/").
func isInsideCgroup(child, parent string) bool {
	if parent == "" {
		return false
	}
	if parent == "/" {
		return true
	}
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+"/")
}

// globMatch is path.Match with one extension: `**` matches any sequence of
// characters including path separators. This is the same convention `git`,
// `gitignore`, and most "recursive glob" implementations use, and is needed
// for profile globs like `/sys/fs/cgroup/**` that should cover every entry
// under a subtree.
//
// Implementation: split the pattern on `**`; require every segment to occur,
// in order, within `s`, with the first segment anchored at the start and the
// last anchored at the end. Each segment is matched via path.Match so the
// usual `*` (single-segment) and `?` characters keep working.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "**")
	if len(parts) == 1 {
		// No "**" — fall back to standard path.Match.
		ok, _ := path.Match(pattern, s)
		return ok
	}

	// Anchored prefix: must match the start of s.
	if parts[0] != "" {
		if !matchPrefix(parts[0], s) {
			return false
		}
		s = s[len(stripTrailingGlob(parts[0])):]
	}
	// Anchored suffix: must match the end of s.
	last := parts[len(parts)-1]
	if last != "" {
		suffixLen := len(stripLeadingGlob(last))
		if len(s) < suffixLen {
			return false
		}
		if !matchSuffix(last, s) {
			return false
		}
		s = s[:len(s)-suffixLen]
	}
	// Middle parts: each must appear in order. (Rare in practice; supported
	// for completeness so patterns like `/a/**/b/**/c` work.)
	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		idx := containsGlob(mid, s)
		if idx < 0 {
			return false
		}
		s = s[idx+len(stripGlobs(mid)):]
	}
	return true
}

// matchPrefix returns true iff `s` starts with a substring matching `pattern`
// under path.Match semantics. It is a coarse anchor: it requires the literal
// portion of the pattern to be present at the start.
func matchPrefix(pattern, s string) bool {
	lit := stripTrailingGlob(pattern)
	if len(s) < len(lit) {
		return false
	}
	ok, _ := path.Match(pattern, s[:len(lit)])
	return ok
}

// matchSuffix is the mirror of matchPrefix for the end of s.
func matchSuffix(pattern, s string) bool {
	lit := stripLeadingGlob(pattern)
	if len(s) < len(lit) {
		return false
	}
	ok, _ := path.Match(pattern, s[len(s)-len(lit):])
	return ok
}

// stripTrailingGlob / stripLeadingGlob / stripGlobs return the literal
// portion of a pattern, removing trailing/leading/all `*` and `?`. Used
// only to size the slice of `s` that the next path.Match consumes.
func stripTrailingGlob(p string) string {
	return strings.TrimRight(p, "*?")
}
func stripLeadingGlob(p string) string {
	return strings.TrimLeft(p, "*?")
}
func stripGlobs(p string) string {
	return strings.ReplaceAll(strings.ReplaceAll(p, "*", ""), "?", "")
}

// containsGlob returns the start index in s of the first substring matching
// `pattern` under path.Match. Returns -1 if no match.
func containsGlob(pattern, s string) int {
	lit := stripGlobs(pattern)
	idx := strings.Index(s, lit)
	if idx < 0 {
		return -1
	}
	end := idx + len(lit)
	ok, _ := path.Match(pattern, s[idx:end])
	if !ok {
		return -1
	}
	return idx
}
