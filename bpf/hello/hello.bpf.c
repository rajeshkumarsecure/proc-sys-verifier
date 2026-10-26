// SPDX-License-Identifier: MIT OR GPL-2.0-only
//
// hello.bpf.c — slice 20 "does the toolchain work?" probe.
//
// Attaches to the sched_process_exec tracepoint and emits one event per
// exec containing (pid, tgid, comm, cgroup_id). This is the smallest
// possible thing that proves end-to-end:
//   1. clang can compile our BPF C with CO-RE,
//   2. cilium/ebpf can load and verify the program,
//   3. ringbuf events flow back to userspace,
//   4. comm + cgroup_id round-trip correctly.
//
// Slices 21 and 22 replace this with LSM hooks for sb_mount / file_open.
// The ringbuf layout is reused; the cgroup_id field is what slice 21's
// per-container filter map will key on.

#include "../psv_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct psv_event {
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // 256 KiB. Generous for a one-event-per-exec probe; the real probes
    // in slices 21/22 can keep the same size — the in-kernel filters
    // keep emit rate proportional to drift, not to host activity.
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// sched_process_exec is a kernel tracepoint that fires once per successful
// execve, after the new mm is installed. The args struct comes from
// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format —
// fields after the common header are filename (data_loc), pid, old_pid.
// We don't need any of those fields; bpf_get_current_*() is enough.
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx) {
    struct psv_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
