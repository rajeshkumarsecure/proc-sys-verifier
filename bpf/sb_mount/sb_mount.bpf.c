// SPDX-License-Identifier: MIT OR GPL-2.0-only
//
// sb_mount.bpf.c — slice 21 PostStartRemount probe.
//
// LSM hook that fires for every successful permission check on a mount
// (mount(2), move_mount(2), fsmount(2), etc. all funnel through
// security_sb_mount). For each call whose originating cgroup is in the
// watched set AND whose target path resolves under /proc or /sys, the
// probe emits one event to a shared ringbuf.
//
// Filter order (cheapest first for THIS hook):
//   1. cgroup-id hash lookup       (single u64 map lookup)
//   2. bpf_d_path of mount target  (kernel walks the dentry chain)
//   3. prefix check: /proc or /sys (constant-time byte comparison)
//
// Note this is slightly reordered from the design doc § 4.2's
// (A,B,C) listing: for sb_mount the action check requires d_path,
// which is more expensive than the cgroup map lookup. The file_open
// probe in slice 22 will follow the design's order because its
// action check is a single bit test.
//
// Truncation policy: if bpf_d_path returns negative (path too long,
// dentry detached, etc.), we still emit the event with target_len
// negative and target[0] = NUL. Userspace treats that as "something
// happened in this watched container; re-scan to find out what."

#include "../psv_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define TARGET_MAX 256

struct sbmount_event {
    __u64 cgroup_id;
    __u32 pid;
    __u32 tgid;
    __s32 target_len; // bpf_d_path return: length on success, negative errno on failure
    char  comm[16];
    char  target[TARGET_MAX];
};

// Set of watched cgroup IDs. Userspace adds one entry per container.
// Value byte is meaningless (presence-only set); we just need O(1)
// "is this cgroup watched?" in the probe.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // kernel cgroup id (st_ino of the cgroup dir)
    __type(value, __u8);
    __uint(max_entries, 4096);
} watched_cgroups SEC(".maps");

// Single ringbuf shared with the userspace loader. 256 KiB; bursts of
// drift get absorbed comfortably and the in-kernel filters keep
// steady-state at ~zero.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// has_proc_or_sys_prefix returns 1 iff s starts with "/proc" or "/sys"
// (with either end-of-string or a following '/'). slen is the string
// length excluding the trailing NUL.
//
// We hand-roll instead of strncmp/memcmp because BPF doesn't provide
// them and the verifier prefers a small, explicitly-bounded function.
static __always_inline int has_proc_or_sys_prefix(const char *s, int slen) {
    if (slen < 4) return 0;
    if (s[0] != '/') return 0;
    if (s[1] == 'p' && s[2] == 'r' && s[3] == 'o' && s[4] == 'c') {
        if (slen == 5) return 1;
        if (slen > 5 && s[5] == '/') return 1;
        return 0;
    }
    if (s[1] == 's' && s[2] == 'y' && s[3] == 's') {
        if (slen == 4) return 1;
        if (slen > 4 && s[4] == '/') return 1;
        return 0;
    }
    return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(psv_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data, int ret) {
    // Honor a prior LSM's deny — don't override another layer's policy.
    if (ret != 0) return ret;

    // Filter 1: cgroup-id. Single hash lookup on a u64.
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&watched_cgroups, &cgid))
        return 0;

    // Reserve the event up front so bpf_d_path has a destination buffer.
    struct sbmount_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    // Common fields.
    e->cgroup_id = cgid;
    __u64 pt = bpf_get_current_pid_tgid();
    e->pid = (__u32)pt;
    e->tgid = (__u32)(pt >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Resolve the target path. bpf_d_path needs struct path *; the LSM
    // hook gives us const, so we cast — the helper does not mutate it.
    long n = bpf_d_path((struct path *)path, e->target, TARGET_MAX);
    e->target_len = (__s32)n;

    if (n <= 0) {
        // Couldn't resolve — emit anyway so userspace knows something
        // happened in this watched container and can re-scan. Skip the
        // prefix filter because there's no path to check.
        e->target[0] = 0;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    // Filter 2: target prefix. bpf_d_path includes the trailing NUL in
    // the returned length; subtract 1 for the string length.
    if (!has_proc_or_sys_prefix(e->target, (int)n - 1)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
