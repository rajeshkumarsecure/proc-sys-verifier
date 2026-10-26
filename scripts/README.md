# scripts/

`test-setup.sh` runs rootless unit tests for installer version selection,
checksum-metadata validation, and stage dispatch. It stubs package installation
and Go installation; it does not change host state. `make test` includes it.

The helper below is separate from these tests:

One-off host-configuration helpers that live outside the install pipeline
(`setup.sh`) and outside the runtime tool (`psv`). Each script edits
host state that requires special care — a reboot, an irreversible
change, or both — and is deliberately surfaced for explicit operator
invocation rather than folded into a stage.

## Scripts

### [enable-bpf-lsm.sh](enable-bpf-lsm.sh)

Adds `bpf` to the kernel's active LSM list by editing
`/etc/default/grub` and running `update-grub`. Requires a reboot to
apply.

**Run only if you want `psv watch`.** The scanner (`psv scan`) doesn't
need BPF LSM and runs fine on any cgroup-v2 host.

```bash
sudo scripts/enable-bpf-lsm.sh
sudo reboot
# after reboot:
cat /sys/kernel/security/lsm   # should include bpf
```

**Safety in three layers:**

1. **Idempotency** — if `bpf` is already in `/sys/kernel/security/lsm`, exits early.
2. **Backup before edit** — `/etc/default/grub.psvbak` is created on first run.
3. **Atomic rewrite + auto-rollback** — the edit goes through `mktemp` + `install`
   (rename(2)), so partial writes are impossible; if `update-grub` fails,
   the script restores the backup and exits non-zero.

**Manual rollback** (before reboot, or any time):

```bash
sudo mv /etc/default/grub.psvbak /etc/default/grub
sudo update-grub
```

**Edge cases the script handles cleanly:**

- Non-Ubuntu/Debian distro → refuses (Fedora uses grubby; not implemented).
- Kernel built without `CONFIG_BPF_LSM=y` → refuses with a clear message.
- Non-grub bootloader (no `/etc/default/grub`) → refuses.
- Not running as root → refuses.
- Already-enabled (`bpf` in active LSM list) → no-op.
- Duplicate-token detection works for `lsm=bpf,foo`, `lsm=foo,bpf`,
  `lsm=foo,bpf,bar`, and the literal-`bpf`-only case.

**Edge cases the script CANNOT detect — operator must decide before running:**

| Case | Why it matters | What to do |
|---|---|---|
| Encrypted root with **TPM-sealed** keys bound to current PCRs | Changing the kernel cmdline changes the PCR measurement; the seal won't unseal at boot | Re-seal manually after the reboot, or skip this script and stay on the scanner-only path |
| **Secure Boot** with custom-enrolled MOK / sb keys bound to specific cmdline hashes | Similar — the cmdline hash changes after the edit | Re-sign or re-enroll; out of scope for the script |
| **Immutable / atomic distros** (Fedora Silverblue, Bottlerocket) | No writable `/etc/default/grub`; the cmdline is set differently | The script's file-existence check refuses cleanly; use the distro's native mechanism (e.g. `rpm-ostree kargs`) instead |
| Hand-edited **`/boot/grub/grub.cfg`** | `update-grub` regenerates this file from `/etc/default/grub` + `/etc/grub.d/*`; manual edits are lost | Back up your changes to `/etc/grub.d/40_custom` first, or skip the script |
| Pinned-cmdline kernels on **managed Kubernetes** (AKS, EKS, GKE) | The cloud provider controls cmdline; you don't | The watcher isn't usable on those nodes regardless; this script doesn't help |

**If in doubt:** run on a VM snapshot first. Reboot. Verify the LSM
list. If anything is wrong, restore the snapshot. The script's
auto-rollback only covers `update-grub` failure; it can't cover "the
edit succeeded but the host won't boot."

**Why not part of `setup.sh`:** `setup.sh` stages are reboot-free and
idempotent by contract. Folding a reboot-requiring step into the
install pipeline would surprise operators who run `setup.sh all`
expecting "ready to use" rather than "ready after the next reboot."

## Adding more scripts

Anything in this directory should:

- Need root, or otherwise touch host state in a way that justifies an
  explicit operator action.
- Be idempotent (safe to re-run).
- Either be reboot-free, or print an unmistakable reboot reminder.
- Take an automatic backup of anything it edits, and document the
  restore command in its header.
- Document the edge cases it CAN'T handle, so the operator can opt out
  before running.

If the script is one-shot and doesn't change boot or persistent host
state (e.g. a data-massaging helper), `tools/` is the better home.
