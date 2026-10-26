// Package discover enumerates running containers on the host and resolves
// the metadata the verifier needs to inspect them: init PID, OCI bundle path,
// and per-namespace handle paths.
//
// Each runtime (runc, containerd, CRI, docker) is fronted by a Source. Callers
// typically use All to fan out across registered sources and dedupe by ID.
package discover

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// Container is the discoverer's output: enough metadata to find the container
// on the host, locate its OCI spec, and enter its namespaces.
type Container struct {
	ID         string            `json:"id"`
	Name       string            `json:"name,omitempty"`
	Runtime    string            `json:"runtime"`
	Status     string            `json:"status,omitempty"`
	InitPID    int               `json:"init_pid"`
	BundlePath string            `json:"bundle_path,omitempty"`
	SpecPath   string            `json:"spec_path,omitempty"`
	NSPaths    map[string]string `json:"ns_paths,omitempty"`
}

// Source is one way to enumerate containers (e.g. runc shellout, containerd
// client, CRI gRPC).
type Source interface {
	Name() string
	Available(ctx context.Context) bool
	List(ctx context.Context) ([]Container, error)
}

// All queries every source that reports Available, merges results, and dedupes
// by container ID. When the same ID is returned by multiple sources, later
// sources do not overwrite earlier ones — order the slice with the most
// authoritative source first (e.g. containerd before docker, since modern
// Docker is containerd underneath).
//
// Errors from individual sources are collected and returned as a joined error;
// the returned slice still contains whatever the working sources produced.
func All(ctx context.Context, sources []Source) ([]Container, error) {
	seen := map[string]struct{}{}
	var out []Container
	var errs []error
	for _, s := range sources {
		if !s.Available(ctx) {
			continue
		}
		cs, err := s.List(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
			continue
		}
		for _, c := range cs {
			if c.ID == "" {
				continue
			}
			if _, ok := seen[c.ID]; ok {
				continue
			}
			seen[c.ID] = struct{}{}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, errors.Join(errs...)
}
