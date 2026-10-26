// Package observe reconstructs the in-container view of /proc (and, in a
// later slice, /sys) by entering the target container's namespaces and
// walking the resulting filesystem.
//
// The observer is the security-sensitive box in the verifier pipeline:
// it enters another process's mount namespace, so its concurrency and
// thread-locking discipline matters. See observe.go for the contract.
//
// The observer is strictly read-only. It never opens anything under /proc or
// /sys for write, never executes anything inside the namespace, and never
// mutates host state.
package observe

// Observed is one entry recorded during the walk: a single path under /proc
// (or, later, /sys) as seen from inside the container's namespaces.
type Observed struct {
	Path       string `json:"path"`
	Mode       string `json:"mode"`                  // e.g. "-rw-r--r--", "Lrwxrwxrwx"
	IsSymlink  bool   `json:"is_symlink,omitempty"`
	LinkTarget string `json:"link_target,omitempty"` // raw, unresolved
	Writable   bool   `json:"writable"`              // file mode w-bit AND containing mount not ro
	MountID    int    `json:"mount_id,omitempty"`    // id of the containing mount, per mountinfo
}

// ObservedSet is the full snapshot produced for one container.
type ObservedSet struct {
	ContainerID string              `json:"container_id"`
	InitPID     int                 `json:"init_pid"`
	Cgroup      CgroupInfo          `json:"cgroup"`
	Entries     map[string]Observed `json:"entries"`
	Mounts      []MountInfo         `json:"mounts"`
}
