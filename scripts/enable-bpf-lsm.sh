#!/usr/bin/env bash
# enable-bpf-lsm.sh — add `bpf` to the kernel's active LSM list.
#
# DISCLAIMER
# ----------
# This script edits /etc/default/grub and runs `update-grub`. Both touch
# boot-critical state. The script makes a backup before editing, uses an
# atomic temp-file rewrite, and rolls back automatically if `update-grub`
# fails — but boot is sharp-edged and no script can cover every host
# configuration. Read this header before running on anything you care
# about, and prefer running it on a snapshot/VM first.
#
# Manual rollback (after a successful run, before reboot):
#     sudo mv /etc/default/grub.psvbak /etc/default/grub
#     sudo update-grub
#
# Why this is its own script and not part of setup.sh
# ---------------------------------------------------
#   - It requires a reboot. setup.sh stages are idempotent and reboot-free.
#   - It's only needed for `psv watch` (Phase 4). The scanner (`psv scan`)
#     runs fine without BPF LSM. Folding this into `setup.sh bpf` would
#     surprise operators who only want the static-scan side of the tool.
#
# What it does
# ------------
#   1. Verifies the kernel was built with CONFIG_BPF_LSM=y.
#   2. Reads GRUB_CMDLINE_LINUX_DEFAULT from /etc/default/grub.
#   3. Computes the new value: existing lsm= list (if any) with `bpf` appended,
#      or adds `lsm=<current /sys/kernel/security/lsm>,bpf` if no lsm= flag is set.
#   4. Backs up /etc/default/grub to /etc/default/grub.psvbak.
#   5. Rewrites /etc/default/grub atomically (mktemp + install) and runs update-grub.
#   6. On update-grub failure, replays full output and restores the backup.
#   7. Prints the reboot reminder.
#
# Idempotent: if bpf is already in /sys/kernel/security/lsm, exits early.
# Re-running after a successful prior edit is a no-op.
#
# Supported / not supported
# -------------------------
# Supported:
#   - Ubuntu / Debian (apt-managed grub2-common with `update-grub`).
#   - Standard initrd boot from /boot on the same root filesystem.
#   - Standard or VM-equivalent BIOS / UEFI without TPM-bound encryption.
#
# Edge cases this script will REFUSE cleanly (won't risk the host):
#   - Non-ubuntu/debian distro (Fedora uses grubby; not handled).
#   - Kernel built without CONFIG_BPF_LSM=y (no point editing GRUB).
#   - Non-grub bootloader (/etc/default/grub missing).
#   - Not running as root.
#   - GRUB_CMDLINE_LINUX_DEFAULT missing or non-quoted in /etc/default/grub.
#
# Edge cases this script CANNOT detect; operator must decide before running:
#   - Encrypted root with TPM-sealed keys tied to current PCR values.
#     Changing the kernel cmdline changes the PCR measurement, which can
#     break the seal-unseal step at boot. If you have such a setup, you
#     already know — and you should re-seal manually after the reboot.
#   - Secure Boot with custom-enrolled MOK or sb keys bound to specific
#     cmdline hashes. Same theme; out of scope.
#   - Immutable / atomic distros (Silverblue, Bottlerocket, etc.). These
#     don't have a writable /etc/default/grub; the script's existence
#     check refuses, but the broader workflow there is rpm-ostree-based
#     and entirely different.
#   - Hand-edited /boot/grub/grub.cfg. The script regenerates this file
#     via update-grub; any manual edits there are lost. This is normally
#     fine (grub.cfg is generated, not authored), but if you've made
#     custom changes, save them first.
#
# If you're not sure your host falls into a normal category: snapshot the
# VM, run this script, reboot, verify boot, and roll forward or back
# from there.

set -euo pipefail

GRUB_FILE="${GRUB_FILE:-/etc/default/grub}"
BACKUP_FILE="${GRUB_FILE}.psvbak"

log()  { printf '\033[1;34m[bpf-lsm]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m    %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[err]\033[0m     %s\n' "$*" >&2; exit 1; }

# 1. Distro + privilege gate.
if [[ ! -r /etc/os-release ]]; then
    err "cannot read /etc/os-release"
fi
. /etc/os-release
case "$ID" in
    ubuntu|debian) ;;
    *) err "unsupported distro: $ID (only ubuntu/debian for now; Fedora uses grubby)" ;;
esac
if [[ $EUID -ne 0 ]]; then
    err "must run as root (re-run under sudo)"
fi

# 2. Kernel support for BPF LSM.
KCONFIG="/boot/config-$(uname -r)"
if [[ ! -r "$KCONFIG" ]]; then
    warn "cannot read $KCONFIG; skipping CONFIG_BPF_LSM check (rare on a generic kernel)"
elif ! grep -q '^CONFIG_BPF_LSM=y' "$KCONFIG"; then
    err "kernel $(uname -r) was built without CONFIG_BPF_LSM=y; install a newer kernel"
fi

# 3. Already enabled? Idempotent early-exit.
ACTIVE_LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
if [[ ",$ACTIVE_LSM," == *",bpf,"* ]]; then
    log "bpf already on active LSM list: $ACTIVE_LSM"
    log "no changes needed; psv watch will load LSM programs"
    exit 0
fi
log "current active LSM list: $ACTIVE_LSM"

# 4. Edit /etc/default/grub.
if [[ ! -f "$GRUB_FILE" ]]; then
    err "$GRUB_FILE not found (non-grub bootloader? this script doesn't support that)"
fi

# Read current GRUB_CMDLINE_LINUX_DEFAULT verbatim. Handles both
# `GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"` and bare assignments.
CUR_LINE="$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE" || true)"
if [[ -z "$CUR_LINE" ]]; then
    err "GRUB_CMDLINE_LINUX_DEFAULT= not found in $GRUB_FILE; refusing to guess"
fi
# Strip the leading key and surrounding quotes to get just the args.
CUR_ARGS="${CUR_LINE#GRUB_CMDLINE_LINUX_DEFAULT=}"
CUR_ARGS="${CUR_ARGS#\"}"
CUR_ARGS="${CUR_ARGS%\"}"

# Compute new args.
#   - If `lsm=...` is already present, append `,bpf` to its value (unless
#     bpf is already in that value as a comma-delimited token).
#   - Otherwise, build `lsm=<active>,bpf` from the current /sys list and add it.
if [[ "$CUR_ARGS" == *"lsm="* ]]; then
    # awk: find the lsm= token; check if `bpf` is already a comma-delimited
    # member of its value (handles head/middle/tail positions uniformly
    # by comma-padding the value before substring matching). Append iff absent.
    NEW_ARGS="$(printf '%s' "$CUR_ARGS" | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^lsm=/) {
                    val = substr($i, 5)
                    padded = "," val ","
                    if (index(padded, ",bpf,") == 0) {
                        $i = $i ",bpf"
                    }
                }
            }
            print
        }
    ')"
else
    # No lsm= flag yet. Build one from the active list so we preserve
    # the kernel's defaults exactly (e.g. lockdown,capability,...).
    NEW_ARGS="$CUR_ARGS lsm=${ACTIVE_LSM},bpf"
fi

if [[ "$NEW_ARGS" == "$CUR_ARGS" ]]; then
    log "GRUB cmdline already declares bpf in lsm= list; nothing to edit"
    log "but /sys/kernel/security/lsm doesn't show it yet — reboot required:"
    log "  sudo reboot"
    exit 0
fi

# 5. Backup + rewrite.
log "current: GRUB_CMDLINE_LINUX_DEFAULT=\"$CUR_ARGS\""
log "new:     GRUB_CMDLINE_LINUX_DEFAULT=\"$NEW_ARGS\""

if [[ ! -f "$BACKUP_FILE" ]]; then
    cp "$GRUB_FILE" "$BACKUP_FILE"
    log "backed up $GRUB_FILE -> $BACKUP_FILE"
else
    log "backup already exists at $BACKUP_FILE (keeping the original original)"
fi

# In-place edit; quote the new value to handle spaces.
# Use a temp file so a write-mid-edit doesn't leave grub broken.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
awk -v new="$NEW_ARGS" '
    /^GRUB_CMDLINE_LINUX_DEFAULT=/ { print "GRUB_CMDLINE_LINUX_DEFAULT=\"" new "\""; next }
    { print }
' "$GRUB_FILE" > "$TMP"
install -m 0644 "$TMP" "$GRUB_FILE"
log "wrote $GRUB_FILE"

# 6. Regenerate grub.cfg.
if ! command -v update-grub >/dev/null 2>&1; then
    err "update-grub not found; install grub2-common or run grub-mkconfig manually"
fi
# Capture full output; only show the tail on success. On failure, replay
# everything and restore the backup so the host isn't left half-configured.
UPDATE_LOG="$(mktemp)"
if ! update-grub > "$UPDATE_LOG" 2>&1; then
    err_rc=$?
    warn "update-grub failed (exit $err_rc); full output below"
    cat "$UPDATE_LOG" >&2
    warn "restoring $GRUB_FILE from $BACKUP_FILE"
    cp "$BACKUP_FILE" "$GRUB_FILE"
    rm -f "$UPDATE_LOG"
    err "aborted; /etc/default/grub restored, /boot/grub/grub.cfg may need manual regen"
fi
tail -3 "$UPDATE_LOG"
rm -f "$UPDATE_LOG"

log ""
log "================================================================"
log " /etc/default/grub updated. Reboot required to apply:"
log "   sudo reboot"
log ""
log " After reboot, verify with:"
log "   cat /sys/kernel/security/lsm     # should include bpf"
log "================================================================"
