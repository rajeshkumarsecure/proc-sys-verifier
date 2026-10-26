// SPDX-License-Identifier: MIT OR GPL-2.0-only
//
// file_open.bpf.c — slice 22 RuntimeWrite probe.
//
// LSM hook that fires for every successful file_open permission check.
// For each call whose:
//   1. file is being opened with FMODE_WRITE,
//   2. originating cgroup is in the watched set,
//   3. resolved path matches an entry in this container's intended-set
//      LPM trie,
// the probe emits one event.
//
// Filter order — THIS hook follows the design doc §4.2 ordering exactly,
// because each step is genuinely cheap and the order minimizes wasted
// work:
//   1. Filter A — action: FMODE_WRITE bit test (single instruction).
//      Reads vastly outnumber writes; this drops ~95% of file_open events
//      before any map lookup.
//   2. Filter B — cgroup: hash lookup on bpf_get_current_cgroup_id().
//      Drops events from unwatched containers.
//   3. Filter C — intended-set: LPM trie lookup keyed by the resolved
//      path. Drops events targeting paths outside the policy surface.
//
// Per-container LPM trie via BPF_MAP_TYPE_ARRAY_OF_MAPS: the watched
// cgroup map's value is a container_handle (u32) that indexes into the
// outer array of inner LPM tries. One trie per watched container; clean
// teardown.
//
// LPM key encoding (must match userspace serialization):
//   - prefixlen is in BITS (LPM convention).
//   - Stored entries are exact-match: the path bytes followed by an
//     explicit '\0', prefixlen = (strlen + 1) * 8. The trailing NUL
//     guards against false positives — without it, "/proc/sysrq-trig"
//     stored as a prefix would falsely match "/proc/sysrq-trigger" or
//     vice versa, since LPM compares bits and doesn't know about path
//     segment boundaries.
//   - Lookups use prefixlen = TARGET_MAX * 8 with the bpf_d_path output
//     copied into the key buffer (which the BPF stack zeroes out). LPM
//     returns the longest stored entry whose prefixlen bits match.
//
// Subtree-match entries (e.g. "mask /proc entirely") are NOT supported
// in slice 22 — the current IntendedSet builder only produces specific
// paths. If a future spec extension adds glob/subtree semantics, the
// userspace serializer would need to encode subtree entries as
// "path/" with prefixlen = strlen * 8 (no NUL guard, trailing slash
// prevents the "/procfoo" false positive). See design doc §4.2.

#include "../psv_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define TARGET_MAX 256

// The f_mode write-access flag is numeric interface value 0x2.
// CO-RE relocates the field; it does not supply preprocessor constants.
#define FMODE_WRITE 0x2

// Policy class values stored in the inner LPM trie. Match the userspace
// PolicyClass enum in internal/watch/intended_set.go.
#define POLICY_MASKED   1
#define POLICY_READONLY 2

// LPM trie key. The kernel requires prefixlen (in bits) as the first
// field; the rest of the struct is the lookup data.
struct lpm_key {
    __u32 prefixlen;
    char  path[TARGET_MAX];
};

// One event per qualifying file_open. Layout matches struct FileOpenEvent
// in internal/watch/file_open.go; both sides must change together.
struct fileopen_event {
    __u64 cgroup_id;
    __u32 pid;
    __u32 tgid;
    __u32 container_handle;
    __u8  policy_class;      // 0 = truncated/unknown, else POLICY_*
    __u8  _pad[3];
    __s32 target_len;        // bpf_d_path return value
    char  comm[16];
    char  target[TARGET_MAX];
};

// watched_cgroups: cgroup_id -> container_handle. The value is the index
// into intended_sets where this container's LPM trie lives. Parallel to
// the slice-21 sb_mount map; slice 23 will introduce a shared Watcher
// struct that keeps both maps in sync.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 4096);
} watched_cgroups SEC(".maps");

// Inner LPM trie template. cilium/ebpf reads this struct to build the
// MapSpec for inner maps. The __array(values, ...) on intended_sets
// below references this template.
//
// max_entries = 256: typical OCI maskedPaths + readonlyPaths total
// around 20 entries; 256 leaves headroom for spec extensions without
// risking kernel memory bloat at scale. With 4096 containers each with
// a fully-populated trie, total cost is ~4096 * 256 * 280B = ~280 MiB —
// in practice trees are sparsely populated so real usage is much less.
struct intended_set_inner {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, 256);
    // LPM tries must use BPF_F_NO_PREALLOC; pre-allocated maps don't
    // support trie node allocation.
    __uint(map_flags, BPF_F_NO_PREALLOC);
} intended_set_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __uint(max_entries, 4096);
    __array(values, struct intended_set_inner);
} intended_sets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// emit reserves and submits a fileopen_event. Factored out because both
// the truncation path and the match path need to emit, with slightly
// different field values.
static __always_inline void emit(struct file *file, __u64 cgid, __u32 handle,
                                  __u8 policy_class, __s32 target_len,
                                  const char *target) {
    struct fileopen_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->cgroup_id = cgid;
    __u64 pt = bpf_get_current_pid_tgid();
    e->pid = (__u32)pt;
    e->tgid = (__u32)(pt >> 32);
    e->container_handle = handle;
    e->policy_class = policy_class;
    e->_pad[0] = 0; e->_pad[1] = 0; e->_pad[2] = 0;
    e->target_len = target_len;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (target_len > 0 && target) {
        __builtin_memcpy(e->target, target, TARGET_MAX);
    } else {
        e->target[0] = 0;
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/file_open")
int BPF_PROG(psv_file_open, struct file *file, int ret) {
    // Honor a prior LSM's deny — don't override another layer's policy.
    if (ret != 0) return ret;

    // Filter A: action mask. f_mode is set by the open(2) caller; the
    // FMODE_WRITE bit tells us the file was opened for write access.
    // Single bit test, runs first because reads dominate file_open
    // traffic on every workload.
    fmode_t fmode = BPF_CORE_READ(file, f_mode);
    if (!(fmode & FMODE_WRITE)) return 0;

    // Filter B: cgroup. Hash lookup on u64.
    __u64 cgid = bpf_get_current_cgroup_id();
    __u32 *handle_p = bpf_map_lookup_elem(&watched_cgroups, &cgid);
    if (!handle_p) return 0;
    __u32 handle = *handle_p;

    // Get this container's intended-set LPM trie. The outer ARRAY_OF_MAPS
    // returns a void* that we pass to bpf_map_lookup_elem on the inner.
    void *inner = bpf_map_lookup_elem(&intended_sets, &handle);
    if (!inner) return 0;

    // Resolve the file's path. struct file embeds struct path as f_path,
    // and bpf_d_path takes a struct path *. The key.path buffer is
    // zero-initialized by virtue of being on the BPF stack with explicit
    // initialization below.
    struct lpm_key key = {};
    // Look up with a max-length prefixlen — LPM will return the longest
    // stored entry whose prefixlen bits match.
    key.prefixlen = TARGET_MAX * 8;

    // New kernels make f_path const; the legacy helper prototype is not const-correct.
    // bpf_d_path only reads the path; keep the kernel pointer, not a stack copy.
    long n = bpf_d_path((struct path *)&file->f_path, key.path, TARGET_MAX);
    if (n <= 0) {
        // Couldn't resolve — emit a truncated event so userspace knows
        // something happened in this watched container with FMODE_WRITE
        // set. Userspace can re-scan the container to recover detail.
        emit(file, cgid, handle, 0, (__s32)n, NULL);
        return 0;
    }

    // Filter C: LPM trie lookup. The stored entries are encoded with the
    // trailing NUL included; our lookup key has the NUL too (bpf_d_path
    // writes it), so an exact match hits.
    __u8 *class_p = bpf_map_lookup_elem(inner, &key);
    if (!class_p) return 0;  // path not in intended set; not a violation

    emit(file, cgid, handle, *class_p, (__s32)n, key.path);
    return 0;
}
