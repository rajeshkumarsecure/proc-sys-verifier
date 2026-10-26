# BPF programs and build inputs

| Input | Purpose |
|---|---|
| `psv_types.h` | Project-authored scalar aliases, numeric BPF identifiers, and partial CO-RE interfaces. |
| `hello/` | Exec-tracepoint smoke probe used by integration tests. |
| `sb_mount/` | Container-scoped mount-attempt observation. |
| `file_open/` | Container-scoped write-mode opens at exact intended paths. |

The Go loaders are in `internal/watch/`. The generated `*_bpfel.go`,
`*_bpfeb.go`, and matching `.o` files are included and must be kept together.
An ordinary `go build` uses them without running clang or attaching BPF.

## Why there is no generated kernel header

The previous full BTF-generated `vmlinux.h` snapshot was removed rather than
relicensed. Its locally assigned GPL-only label was not verified upstream
licensing provenance. The replacement is
[psv_types.h](psv_types.h), a small handwritten interface header under the same
`MIT OR GPL-2.0-only` license as the project-owned probes.

The probes need only two internal `file` members: `f_mode` and `f_path`.
The header describes these members and the two pointer members of `path`,
without reproducing a complete kernel structure or any kernel implementation.
`preserve_access_index` records relocations so cilium/ebpf resolves the actual
field offsets from the target kernel's BTF. The local structure layout is not
the target memory layout and must not be used to read arbitrary kernel fields.
Target BTF is still required when loading the CO-RE probes.

The header also states fixed-width scalar aliases and the four map-type
identifiers plus the no-preallocation flag used here. These numeric interface
values are checked against the compiled map specifications by rootless tests.
No system kernel-header include paths or machine-specific BTF dump are required
to regenerate the objects.

## Regeneration

```sh
make bpf
make test
make vet
```

Generation uses the bpf2go version locked by the Go module
(cilium/ebpf v0.21.0), not an independently installed `@latest` generator.
It needs clang with the BPF backend, llvm-strip, and libbpf development headers.
Generation does not load/attach the programs. Do not edit the generated Go
bindings or objects manually, and do not restore a full generated kernel dump
as an unreviewed build input.

The release-preparation objects were regenerated using clang 18.1.3 and Ubuntu
`libbpf-dev 1:1.3.0-2build2`. bpf2go maps source paths to relative paths rather
than embedding the workspace directory.

When adding a kernel field, add only the interface declaration required, retain
CO-RE annotations, and test relocation against shifted and missing-field
targets. Rebuild both byte orders. Confirm that helper arguments remain kernel
pointers where required; for example, `bpf_d_path` must receive the kernel's
`path` object rather than a stack copy.

## Validation of the header replacement

- Both little- and big-endian objects rebuild and parse without root.
- Rootless tests exercise shifted, reordered, and anonymous-member target
  layouts and missing required fields.
- All six objects retain their map ABI and program interfaces.
- After relocation to the release-preparation host's BTF, all three native
  probe instruction sequences are identical to the former snapshot-based build.
- Eight focused live integration tests passed on Linux 7.0.0-38-generic x86_64:
  one exec round-trip, three mount-filter/lifecycle tests, and four file-open
  action/path/cgroup-filter tests. Temporary test cgroups were cleaned up.

This is not a claim that every kernel/platform has been tested. Further live
tests must run only on an explicitly authorized disposable test host.

## License and provenance

Project-owned probes and `psv_types.h` are `MIT OR GPL-2.0-only`. The ELF marker
remains `Dual MIT/GPL`: Linux BPF LSM programs require GPL-compatible licensing,
and removing a header does not remove that requirement.

The system libbpf macro headers retain `LGPL-2.1 OR BSD-2-Clause`; the BSD option
is used here. Generated helper definitions and their upstream notices are not
relicensed. The project grant does not replace third-party conditions or imply
that every file in the distribution is MIT-only.

See [LICENSING.md](../LICENSING.md) for the scoped review conclusion and primary
sources, and
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for retained upstream notices.
