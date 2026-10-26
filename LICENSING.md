# Licensing

## Project-owned code

| Material | License |
|---|---|
| Project-owned Go code, documentation, policies, build/setup helpers | MIT, unless an individual file states otherwise |
| Generated Go wrapper code | Project-owned portions are MIT; bpf2go template-derived portions retain the upstream MIT notice in `third_party/licenses/cilium-ebpf/LICENSE`; embedded BPF bytes have the separate terms below |
| `bpf/hello/hello.bpf.c`, `bpf/sb_mount/sb_mount.bpf.c`, `bpf/file_open/file_open.bpf.c` | MIT OR GPL-2.0-only |
| Project-authored `bpf/psv_types.h` partial CO-RE interface declarations | MIT OR GPL-2.0-only |
| Included compiled BPF objects under `internal/watch/` | Project-owned program portions use MIT OR GPL-2.0-only; incorporated libbpf material retains its BSD-2-Clause conditions and notices |

The copyright holder authorized the dual licensing of project-owned BPF programs
when preparing this source distribution. Their SPDX headers now agree with the
existing ELF declaration, `Dual MIT/GPL`. The MIT root license does not
override these exceptions or any upstream license.

The MIT alternative applies to project-owned BPF source and interface declarations.
It does not replace upstream licenses or notices on incorporated material. There
is no generated kernel-type snapshot or locally assigned GPL-only header in the
current source distribution.

The BPF ELF `license` section is a declaration checked by the Linux kernel. It is
not a replacement for a copyright license or license text. BPF LSM programs must
be GPL-compatible, including when their code does not explicitly call a
GPL-only helper. MIT is GPL-compatible; GPL-compatible does not mean GPL-only.
The existing `Dual MIT/GPL` declaration is retained. Removing the generated
header does not remove the kernel's LSM licensing requirement. See the
[Linux BPF licensing guidance](https://docs.kernel.org/bpf/bpf_licensing.html).

User-space Go code and kernel-side BPF programs are separately licensed
components. Shipping BPF bytecode embedded in a Go executable does not remove
the BPF or third-party distribution obligations. Include the applicable license
texts and notices with binary releases. Keep the corresponding BPF sources and
generation inputs available; provide corresponding source as required when
redistributing under the GPL option.

License texts:

- [MIT, project default](LICENSE), also retained in [LICENSES/MIT.txt](LICENSES/MIT.txt)
- [Apache-2.0](LICENSES/Apache-2.0.txt), retained for dependencies using that license
- [GPL-2.0-only](LICENSES/GPL-2.0-only.txt)
- [BSD-2-Clause](LICENSES/BSD-2-Clause.txt), used by upstream libbpf build headers

## Third-party and generated material

Third-party code is not relicensed. Its original notices are retained under
[third_party/licenses/](third_party/licenses/); see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

### Generated-header issue resolved by replacement (2026-10-26)

An earlier release-preparation copy contained a large `vmlinux.h` BTF dump with
a locally added GPL-2.0-only marker. That designation was not supplied by bpftool
and did not establish the upstream licensing status of all generated declarations.
It has not been used as a basis for relicensing Linux material.

The generated snapshot is now deleted. All three probes instead include
[bpf/psv_types.h](bpf/psv_types.h), a handwritten project interface header with
fixed-width scalar aliases, the required BPF numeric identifiers, opaque type
names, and only the `file`/`path` members needed for CO-RE access. It contains no
kernel function implementations, copied kernel inline functions, or generated
kernel type dump. Its layouts are deliberately partial; target field offsets
are resolved from the running kernel's BTF by the loader, not hard-coded from
the former snapshot.

The licensing decision applies to the authored interface header, not to every
BTF-generated header or all kernel declarations. The owner-authorized
MIT OR GPL-2.0-only grant covers this project's BPF programs and interface
header; upstream components retain their own terms. This removes the concrete
generated-snapshot licensing assumption without claiming to settle a general
copyright question about BTF output.

The six BPF objects and their Go bindings were regenerated. Both byte orders
pass relocation tests against shifted, reordered, and anonymous-member layouts;
missing required fields are rejected or poison the relocation rather than
silently using an offset. On Linux 7.0.0-38-generic x86_64, the native-endian
host-relocated instructions are identical to the previous objects, and all eight
focused live watcher integration tests passed with temporary test resources
cleaned up. These results validate this replacement, not every kernel/platform.

Evidence used for this resolution:

- [Linux BPF licensing](https://docs.kernel.org/bpf/bpf_licensing.html):
  distinguishes user-space packaging, GPL-compatible helpers, and LSM program
  requirements. It does not establish a universal license for BTF-generated C.
- [libbpf v1.3.0 bpf_helpers.h](https://github.com/libbpf/libbpf/blob/v1.3.0/src/bpf_helpers.h),
  [bpf_tracing.h](https://github.com/libbpf/libbpf/blob/v1.3.0/src/bpf_tracing.h),
  and [bpf_core_read.h](https://github.com/libbpf/libbpf/blob/v1.3.0/src/bpf_core_read.h):
  carry `LGPL-2.1 OR BSD-2-Clause`, not a GPL-only declaration.
- [Linux v6.8 BPF UAPI identifiers](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/bpf.h):
  reference for the numeric map types/flags, not an imported implementation.
- [BPF CO-RE explanation by Andrii Nakryiko](https://nakryiko.com/posts/bpf-portability-and-co-re/):
  explains matching field names/types to target BTF and relocating field offsets.
  This is a technical source, not an upstream license grant.

Build-time libbpf headers retain their upstream licensing. This build uses their
BSD-2-Clause option. The generated objects do not dynamically link libbpf; the Go
loader uses cilium/ebpf.

These records document the inspected source distribution, not a blanket legal
opinion, a dependency-vulnerability audit, or clearance for independently added
material. Future dependency/toolchain updates and binary releases must preserve
the corresponding notices and source obligations.
