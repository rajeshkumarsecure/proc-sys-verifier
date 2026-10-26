# proc-sys-verifier

PSV is a Linux container runtime verifier. It compares the container's observed
view of `/proc` and `/sys` with the restrictions declared in its OCI runtime
specification, and can monitor selected runtime activity using eBPF.

This repository contains the detector, policies, tests, and build/setup helpers.
It does not include exploit PoCs, vulnerable-runtime provisioning, presentation
material, private research notes, or raw workload measurements.

## Detection

| Class | Signal |
|---|---|
| `WritableDrift` | A literal masked/read-only specification entry is observed as writable. |
| `OutOfPolicyRedirect` | A symlink's lexically resolved target is a spec-declared masked path. |
| `CgroupDelegationExposure` | A writable cgroup-v2 control file is classified outside the container's own subtree. |
| `PostStartRemount` | A watched container attempts a mount operation targeting `/proc` or `/sys`. |
| `RuntimeWrite` | A watched container reaches the file-open LSM hook with write mode for an exact spec-protected path. |

Expected delegation within the container's own cgroup subtree is reported as
informational `DelegatedLeaf` context rather than an exposure deviation.

PSV is detection tooling, not a sandbox or an enforcement mechanism. A clean
report is not proof that a container cannot escape.

## Requirements

- Linux with a unified cgroup-v2 hierarchy; Linux 6.1 or newer is the project
  baseline.
- Go 1.24.0 or newer to build. The installer defaults to Go 1.26.10; a newer
  installed stable Go version is not downgraded. Keep production toolchains
  patched; the minimum supported version is not a security-update policy.
- `make`, Bash, and `jq` for the documented build/setup-helper test commands.
  The detector itself does not invoke `jq`.
- `runc` on `PATH`, access to its runtime state and the OCI specification, and
  host privileges sufficient to inspect the target mount namespace. Running as
  root is the documented starting point for live observation. Unit tests and
  `inspect-spec` do not need root or a runtime.
- Discovery currently uses the `runc` CLI, including known runc-state roots used
  by containerd, Docker, and Kubernetes deployments. Direct CRI/containerd-socket
  discovery and non-runc runtimes are not implemented.

For `watch`, the host additionally needs `CONFIG_BPF_LSM=y`, BTF, and `bpf` in the
active LSM list, plus privileges to load/attach BPF programs. Managed nodes may
not permit that configuration. The scanner does not require BPF LSM.

The generated BPF Go bindings and objects are included, so an ordinary build
does not need clang, bpftool, or BPF-LSM support.

## Build and test

```sh
make build
make test
make vet
./bin/psv version
./bin/psv inspect-spec internal/spec/testdata/runc-default-config.json
```

No Git repository is required to build; the version defaults to `dev`.

On Ubuntu/Debian, optional setup stages are:

```sh
./setup.sh --help
sudo ./setup.sh core       # Go and build prerequisites
sudo ./setup.sh runtimes   # core + runc/containerd packages
sudo ./setup.sh bpf        # core + BPF development tools
```

Setup changes host packages and may replace an older `/usr/local/go`
installation, retaining it at `/usr/local/go.psv-backup`. It does not explicitly
manage runtime services, but distribution package hooks may enable/start them.
It does not change the kernel command line. Do not run it on a shared production
host without reviewing the changes. Set `GO_VERSION` to a specific stable version
>= 1.24.0 to override the installer default.

Enable BPF LSM only after reading [scripts/README.md](scripts/README.md).
That separate helper edits boot configuration and requires a reboot.

## Usage

```sh
sudo ./bin/psv list
sudo ./bin/psv observe <container-id>
sudo ./bin/psv scan <container-id>
sudo ./bin/psv scan -policy systemd-cgroup -format tty -no-color <container-id>
sudo ./bin/psv scan -policy-file ./policy.yaml <container-id>

mkdir -m 700 artifacts
sudo ./bin/psv watch -output artifacts/events.jsonl -timeout 30s <container-id>
sudo ./bin/psv scan -ingest artifacts/events.jsonl <container-id>
```

Use `psv <command> -h` for flags. `scan` produces a JSON report by default.
`watch` produces JSONL envelopes containing `container_id` and `deviation`.
Watch events are unfiltered; policy is applied when they are ingested by `scan`.

Built-in profiles are `default`, `privileged`, and `systemd-cgroup`. Profiles
support `class`, `path_glob` (including `**`), and cgroup scopes
`delegated_subtree` and `above_delegated_root`. Deny rules take precedence over
allow rules. Profile definitions are in
[internal/policy/builtin/](internal/policy/builtin/).

Treat OCI configurations, observed paths, and output reports as potentially
sensitive. Review and sanitize them before sharing; ignore patterns are not an
access-control or secret-detection mechanism.

## Limitations

- Static checks are snapshots, not an atomic or continuous integrity guarantee.
  They depend on the available OCI spec and current visibility.
- Writable-drift comparison checks literal intended entries, not every
  descendant of read-only directory entries. Symlink checks are lexical.
- Character/block devices are treated as not security-relevantly writable,
  including the inert devices used to implement masked files. Stacked mounts
  can also affect static mount attribution.
- The file-open watcher uses exact intended paths, not recursive subtree
  matching. It observes write-mode opens, not completed writes or their
  contents. Writes through already-open descriptors are outside that hook.
- Kernel checks that reject an open before `lsm/file_open` produce no watcher
  event; legitimate read-only mounts commonly do this.
- Mount events are attempts observed at an LSM hook, not proof that a mount
  succeeded or that a persistent post-start change was confirmed.

See [design/architecture.md](design/architecture.md) for the data flow and safety
boundary.

## Integration tests

```sh
sudo -E "$(command -v go)" test -tags integration ./...
```

Only run these on a disposable, explicitly authorized test host. Unlike unit
tests, they enter namespaces, load BPF programs, and create temporary test
cgroups/mounts. Some require an already-running ordinary runc container; missing
preconditions are reported as skips. Exploit-specific tests are not included.

To regenerate the included BPF objects after changing their source:

```sh
make bpf
```

See [bpf/README.md](bpf/README.md) for provenance and regeneration requirements.

## License and disclosure

The Go detector, project documentation, and helpers are MIT-licensed unless stated
otherwise. Project-owned BPF C programs and their minimal CO-RE interface header
are `MIT OR GPL-2.0-only`; the probes retain the kernel-compatible `Dual MIT/GPL`
declaration. The former generated kernel-type snapshot has been removed, not
relicensed. Builds use the small, project-authored
[bpf/psv_types.h](bpf/psv_types.h) instead. Third-party components retain their
original licenses and notices, including the BSD option for libbpf build headers.
See [LICENSING.md](LICENSING.md) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), which are part of the distribution.

Runtime/provider-specific suspected vulnerabilities must go through the
appropriate private disclosure channel before public discussion. Do not post
secrets, raw workload configurations, or undisclosed findings in public issues.
