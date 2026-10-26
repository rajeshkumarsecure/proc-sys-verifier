# Third-party notices

This inventory covers the detector's runtime Go module dependencies, the Go
runtime/standard library, and BPF generation inputs. It does not vendor dependency
source code or claim that every module listed in `go.sum` is linked into PSV.

| Component | Inspected version | Upstream license / retained notices |
|---|---|---|
| opencontainers/runtime-spec | v1.3.0 | Apache-2.0; [LICENSE](third_party/licenses/runtime-spec/LICENSE) |
| cilium/ebpf, including bpf2go | v0.21.0 | MIT; [LICENSE](third_party/licenses/cilium-ebpf/LICENSE) |
| golang.org/x/sys | v0.37.0 | BSD-3-Clause; [LICENSE](third_party/licenses/golang-x-sys/LICENSE), [PATENTS](third_party/licenses/golang-x-sys/PATENTS) |
| gopkg.in/yaml.v3 | v3.0.1 | MIT for the listed libyaml-derived files; Apache-2.0 for the remainder; [LICENSE](third_party/licenses/yaml-v3/LICENSE), [NOTICE](third_party/licenses/yaml-v3/NOTICE) |
| Go runtime and standard library | Go 1.24.0 baseline; installer default Go 1.26.10 | BSD-3-Clause and upstream per-file notices; [LICENSE](third_party/licenses/go/LICENSE), [PATENTS](third_party/licenses/go/PATENTS) |
| libbpf build headers | Ubuntu libbpf-dev 1:1.3.0-2build2 | Macro headers identify LGPL-2.1 OR BSD-2-Clause; BSD option used here. Generated helper definitions derive from kernel UAPI documentation. Full packaged [COPYRIGHT](third_party/licenses/libbpf/COPYRIGHT) retains upstream notices, including the UAPI syscall exception. |

The former generated kernel-type snapshot is not part of this distribution.
[bpf/psv_types.h](bpf/psv_types.h) is a project-authored partial interface header,
not an imported Linux implementation or full BTF dump. The replacement and its
technical/reference sources are documented in
[LICENSING.md](LICENSING.md#generated-header-issue-resolved-by-replacement-2026-10-26).

The project's switch to MIT applies only to project-owned material. In particular,
runtime-spec and the Apache-licensed portions of yaml.v3 retain their original
terms. The full Apache-2.0 text is retained in
[LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).

The default Go dependency versions are locked in `go.mod` and `go.sum`.
`go generate` invokes bpf2go through that module version, not an unpinned
`@latest` installation.

The BPF objects are generated using system libbpf headers including
`bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_tracing.h`, and `bpf_core_read.h`.
Their original notices remain applicable to incorporated material. The
project-owned BPF dual-license grant does not replace those notices.

The retained Go license files were copied from the baseline Go installation.
When building/distributing with a different toolchain, inspect its full upstream
notices, including per-file notices, and update the distributed notices if
necessary. Compiler/tool packages used only during development are not bundled.
