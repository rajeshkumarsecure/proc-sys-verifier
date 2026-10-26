// Package watch attaches eBPF probes to live containers and streams the
// resulting events as structured Deviations. The watcher is the Phase 4
// counterpart to internal/observe's one-shot scan: same JSON schema,
// same policy filter, continuous instead of point-in-time.
//
// Slice 20 ships only the toolchain proof (a sched_process_exec
// tracepoint). Slices 21 and 22 add the real probes (sb_mount,
// file_open) and the per-container filter maps. Slice 23 wires the
// whole thing under `psv watch <container>`.
//
// The bpf2go directives below generate Go bindings for each BPF object
// when go generate runs. Generation requires clang + libbpf headers; the
// generated files are checked in so end users don't need clang.
package watch

// Hello is the slice-20 probe — proves the build/load/attach/ringbuf
// chain works end-to-end. Generates hello_bpfel.go (little-endian) and
// hello_bpfeb.go (big-endian) plus the matching compiled object files.
//
// Flags:
//   -target bpfel,bpfeb   build for both endiannesses (Go selects at compile time)
//   -cflags "..."          pulled from CFLAGS env; -O2 is required for the
//                          BPF verifier to accept the resulting bytecode.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cflags "-O2 -Wall -Werror -I../../bpf" hello ../../bpf/hello/hello.bpf.c

// Sbmount is the slice-21 probe: lsm/sb_mount + cgroup-id filter +
// /proc-or-/sys prefix check on the resolved target. Emits one event
// per qualifying mount call into a ringbuf shared with userspace.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cflags "-O2 -Wall -Werror -I../../bpf" sbmount ../../bpf/sb_mount/sb_mount.bpf.c

// Fileopen is the slice-22 probe: lsm/file_open + FMODE_WRITE filter +
// cgroup-id filter + per-container intended-set LPM trie lookup. Emits
// one event per write-open against a policy-protected path. The
// per-container LPM trie lives in a BPF_MAP_TYPE_ARRAY_OF_MAPS indexed
// by the container_handle that the watched_cgroups map's value carries.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cflags "-O2 -Wall -Werror -I../../bpf" fileopen ../../bpf/file_open/file_open.bpf.c
