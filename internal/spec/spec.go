// Package spec loads an OCI runtime configuration and projects it into an
// IntendedSet: the operator-declared shape of /proc, /sys, and any other mount
// destinations the container is supposed to see.
//
// The IntendedSet is the "what should be true" side of the verifier's three-way
// contract (intended / enforced / observed).
package spec

import (
	"encoding/json"
	"fmt"
	"os"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

// Kind classifies how a path is meant to appear inside the container.
type Kind string

const (
	// KindMasked: the path is bind-mounted over with /dev/null (file) or a
	// read-only tmpfs (directory). Reads return empty or fail.
	KindMasked Kind = "masked"
	// KindReadOnly: the path is remounted read-only after the rootfs is set up.
	KindReadOnly Kind = "readonly"
	// KindMounted: the path is an explicit mount in config.json mounts[].
	KindMounted Kind = "mounted"
)

// Entry is a single intended fact about one path inside the container.
type Entry struct {
	Path    string   `json:"path"`
	Kind    Kind     `json:"kind"`
	Source  string   `json:"source,omitempty"`
	Type    string   `json:"type,omitempty"`
	Options []string `json:"options,omitempty"`
}

// Namespace records one entry from linux.namespaces.
// Path is set when the container joins an existing namespace (e.g. hostPID
// leaves Path empty for that type — meaning a new namespace is created).
type Namespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

// IntendedSet is the projection of an OCI runtime spec the verifier cares about.
type IntendedSet struct {
	Entries    map[string]Entry `json:"entries"`
	Namespaces []Namespace      `json:"namespaces"`
}

// Load reads an OCI config.json from disk and returns its IntendedSet.
func Load(path string) (*IntendedSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	return Parse(raw)
}

// Parse builds an IntendedSet from the bytes of an OCI config.json.
func Parse(data []byte) (*IntendedSet, error) {
	var s rspec.Spec
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	return FromSpec(&s), nil
}

// FromSpec projects a parsed runtime-spec Spec into an IntendedSet.
//
// Precedence when the same path is declared in multiple places:
//
//	mounts[] > maskedPaths > readonlyPaths
//
// (Mounts are the most specific declaration; masking is stronger than ro.)
func FromSpec(s *rspec.Spec) *IntendedSet {
	out := &IntendedSet{Entries: map[string]Entry{}}

	if s.Linux != nil {
		for _, p := range s.Linux.ReadonlyPaths {
			out.Entries[p] = Entry{Path: p, Kind: KindReadOnly}
		}
		for _, p := range s.Linux.MaskedPaths {
			out.Entries[p] = Entry{Path: p, Kind: KindMasked}
		}
		for _, n := range s.Linux.Namespaces {
			out.Namespaces = append(out.Namespaces, Namespace{
				Type: string(n.Type),
				Path: n.Path,
			})
		}
	}
	for _, m := range s.Mounts {
		out.Entries[m.Destination] = Entry{
			Path:    m.Destination,
			Kind:    KindMounted,
			Source:  m.Source,
			Type:    m.Type,
			Options: append([]string(nil), m.Options...),
		}
	}
	return out
}
