package observe

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// CgroupInfo records the container's cgroup-v2 position and namespace
// identity. Collected on the host before setns; reflects the kernel's view
// of the container's init process.
//
// This information is the input the differ's CgroupDelegationExposure
// classifier needs to decide whether a writable /sys/fs/cgroup/* file is
// "delegated and contained" or "reachable above the delegated root".
type CgroupInfo struct {
	// Path is the container's own cgroup, e.g. "/user.slice/user-1000.slice/demo".
	// Read from /proc/<initpid>/cgroup. On cgroup v2 this file has exactly one
	// line of the form "0::/path". Empty when the file is missing or unparseable
	// (best-effort — the rest of the observer should still succeed).
	Path string `json:"path"`

	// NamespaceID is the container init's cgroup namespace identity, e.g.
	// "cgroup:[4026532149]". Read from /proc/<initpid>/ns/cgroup (a symlink).
	NamespaceID string `json:"namespace_id"`

	// HostNamespaceID is /proc/1/ns/cgroup's target for comparison.
	HostNamespaceID string `json:"host_namespace_id"`

	// NamespaceShared is true when the container init shares the host's
	// cgroup namespace (no cgroup-ns isolation). Pre-computed for the
	// renderer/differ; equivalent to NamespaceID == HostNamespaceID.
	NamespaceShared bool `json:"namespace_shared"`
}

// readCgroupInfo collects CgroupInfo for the container whose init PID is
// `initPID`. All reads happen on the host's /proc; no setns required.
func readCgroupInfo(initPID int) CgroupInfo {
	var info CgroupInfo
	info.Path = readCgroupPath(fmt.Sprintf("/proc/%d/cgroup", initPID))
	info.NamespaceID = readNamespaceID(fmt.Sprintf("/proc/%d/ns/cgroup", initPID))
	info.HostNamespaceID = readNamespaceID("/proc/1/ns/cgroup")
	info.NamespaceShared = info.NamespaceID != "" &&
		info.NamespaceID == info.HostNamespaceID
	return info
}

// readCgroupPath parses the cgroup v2 path from a /proc/<pid>/cgroup file.
//
// cgroup v2 emits exactly one line: "0::/path/to/cgroup". On hybrid hosts the
// file may contain additional v1 controller lines; we ignore them — the v2
// line is the one tagged with hierarchy id "0".
//
// Returns "" on any read or parse failure. This is best-effort: the rest of
// the observer should still produce useful output even if cgroup capture
// fails.
func readCgroupPath(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("0::")) {
			continue
		}
		return strings.TrimSpace(string(line[3:]))
	}
	return ""
}

// readNamespaceID resolves a /proc/<pid>/ns/<ns> symlink and returns its
// target, e.g. "cgroup:[4026532149]". Returns "" on any failure.
func readNamespaceID(symlink string) string {
	target, err := os.Readlink(symlink)
	if err != nil {
		return ""
	}
	return target
}
