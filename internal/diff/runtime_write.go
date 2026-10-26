// runtime_write.go — Phase 4 deviation classes that come from the
// eBPF watcher rather than the static scan.
//
// Slice 23 lands the wire types; the watch package (internal/watch)
// populates them from its sb_mount and file_open probes. The
// renderer's classMetaTable + the policy DSL pick them up
// automatically because the existing dispatch is class-keyed.
//
// PostStartRemount was declared back in slice 1 next to ClassWritableDrift
// for forward-compatibility; we move it to live with the typed payload
// here. The Class constant moves too — keeping the source of truth in
// one place per class — but the string value is unchanged so any
// downstream consumer (test, JSON, log aggregator) stays bit-compatible.

package diff

const (
	// ClassRuntimeWrite flags a write-open against a path the OCI spec
	// declared masked or read-only. Emitted by the eBPF file_open
	// watcher in real time; the static scan can't catch it because
	// the file was correctly masked at scan time and the write
	// happens between scans.
	ClassRuntimeWrite Class = "RuntimeWrite"
)

// PostStartRemountObserved captures one mount call the watcher saw
// inside a watched container's namespaces, targeting /proc or /sys.
//
// The watcher emits one of these per qualifying mount syscall. The
// `Truncated` flag is set when bpf_d_path couldn't resolve the full
// target path (rare, but recoverable — userspace can re-scan to fill
// in the gap).
type PostStartRemountObserved struct {
	CgroupID   uint64 `json:"cgroup_id"`
	ActorPID   uint32 `json:"actor_pid"`
	ActorTGID  uint32 `json:"actor_tgid"`
	ActorComm  string `json:"actor_comm"`
	OccurredAt string `json:"occurred_at,omitempty"` // RFC3339Nano; set by the userspace decoder
	Truncated  bool   `json:"truncated,omitempty"`
}

// PostStartRemountIntended is intentionally minimal — the spec didn't
// declare anything about post-start mounts other than "the masked /
// readonly paths shouldn't be rewritable." The class itself encodes
// that contract; this struct is a placeholder for the renderer's
// uniform shape.
type PostStartRemountIntended struct {
	// Class echoes the policy class the affected path carried, when
	// the watcher could determine it (file under maskedPaths /
	// readonlyPaths). Empty when the mount target wasn't in the
	// container's intended set — those events are emitted only for
	// the operator's situational awareness, not as policy violations.
	Class string `json:"class,omitempty"` // "masked" | "readonly" | ""
}

// RuntimeWriteObserved captures one write-open the file_open watcher
// caught inside a watched container, targeting an intended-set path.
//
// Fields mirror PostStartRemountObserved for renderer uniformity; the
// `Policy` field carries the policy class the LPM trie lookup
// returned, which is what classified this open as a violation.
type RuntimeWriteObserved struct {
	CgroupID   uint64 `json:"cgroup_id"`
	ActorPID   uint32 `json:"actor_pid"`
	ActorTGID  uint32 `json:"actor_tgid"`
	ActorComm  string `json:"actor_comm"`
	OccurredAt string `json:"occurred_at,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// RuntimeWriteIntended carries the policy class the path was declared
// under in the OCI spec. Either "masked" or "readonly"; the watcher
// only emits events for paths it found in the intended-set LPM trie,
// so this field is always populated for class=RuntimeWrite events.
type RuntimeWriteIntended struct {
	Class string `json:"class"` // "masked" | "readonly"
}
