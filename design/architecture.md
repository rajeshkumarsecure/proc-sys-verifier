# Detector architecture

## Data flow

1. Discover a running container through `runc` and supported runtime-state roots.
2. Load its OCI `config.json` into an `IntendedSet`.
3. Read the container's host-side mountinfo and cgroup/namespace identity.
4. Inspect `/proc` and `/sys` from its mount namespace, producing an `ObservedSet`.
5. Compare intended and observed state, apply a built-in or external policy, and
   render a JSON or terminal report.

The observer uses a dedicated locked OS thread, unshares filesystem attributes
before entering the mount namespace, and opens required namespace descriptors
before switching namespaces. It does not enter the PID namespace. Mountinfo is
read through the container init PID on the host before switching namespaces.

The scanner does not open inspected entries for writing. Writability checks use
access checks and mount information, with special handling for inert masked
devices. This is an observation model, not a test write or an enforcement action.

## Cgroup exposure

The observer captures the container's cgroup path and namespace identity. The
differ translates visible control-file paths through the cgroup mount root and
compares the resulting host-relative paths with the container's subtree.

Writable controls within that subtree become informational annotations;
controls classified outside it become `CgroupDelegationExposure`. Namespace
identity alone is not enough to determine safe delegation.

## Runtime observation

`watch` attaches BPF LSM probes to `sb_mount` and `file_open`. Cgroup filters limit
events to the selected container. The file-open probe additionally consults an
exact-match intended-path LPM trie. Both probes emit structured events through
ring buffers; Go translates them into the deviation schema.

`scan -ingest` merges JSONL watch envelopes with a static scan before applying
policy. The watch stream itself is unfiltered by user-facing allow/deny profiles.
These hooks report attempts at their observation points, not confirmed final
system-call results, completed writes, or a full filesystem history.

## Safety and scope

The detector is read-only with respect to inspected target files. Loading BPF
programs and creating BPF maps are explicit host instrumentation, not changes to
the target's filesystem. Setup and integration tests have a different safety
boundary: they may modify host packages, boot configuration, or temporary test
resources and must be invoked separately on an authorized host.

The CLI's current exact-path/subtree, device, symlink, and mount-attribution
limitations are documented in the root README. No particular CVE or container
escape is claimed to be comprehensively detected.
