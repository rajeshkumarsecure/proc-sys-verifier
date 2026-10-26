#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

GO_VERSION="${GO_VERSION:-1.26.10}"
MIN_GO_VERSION=1.24.0

usage() {
  cat <<'EOF'
Usage: ./setup.sh [core|runtimes|bpf]
  core      Install Go and build prerequisites (default).
  runtimes  Also install runc/containerd; package hooks may start services.
  bpf       Also install clang/LLVM, libbpf headers and bpftool packages.

Ubuntu/Debian only. Changes host packages; review before running.
GO_VERSION selects a stable Go release >= 1.24.0 (default: 1.26.10).
An installed version newer than the selected version is not downgraded.
An older /usr/local/go is retained at /usr/local/go.psv-backup.
BPF LSM is NOT enabled automatically; see scripts/README.md.
EOF
}

log() { printf '[setup] %s\n' "$*"; }
err() { printf '[setup] %s\n' "$*" >&2; }

version_at_least() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  [[ "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$2" ]]
}

validate_go_version() {
  if ! version_at_least "$GO_VERSION" "$MIN_GO_VERSION"; then
    err "GO_VERSION must be a stable x.y.z version >= $MIN_GO_VERSION"
    return 2
  fi
}

sudo_() {
  if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

preflight() {
  if [[ ! -r /etc/os-release ]]; then
    err "cannot read /etc/os-release"
    return 1
  fi
  local ID
  . /etc/os-release
  case "$ID" in
    ubuntu|debian) ;;
    *) err "unsupported distribution: $ID"; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|aarch64) ;;
    *) err "unsupported architecture: $(uname -m)"; return 1 ;;
  esac
}

apt_install() {
  if [[ "${apt_updated:-0}" == 0 ]]; then
    sudo_ apt-get update
    apt_updated=1
  fi
  sudo_ env DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends "$@"
}

installed_go_version() {
  local go_bin
  if [[ -x /usr/local/go/bin/go ]]; then
    go_bin=/usr/local/go/bin/go
  elif go_bin=$(command -v go); then
    :
  else
    printf '0.0.0\n'
    return
  fi
  "$go_bin" version | awk '{sub(/^go/, "", $3); print $3}'
}

go_archive_checksum() {
  local checksum
  checksum=$(jq -er --arg version "go$1" --arg arch "$2" \
    'first(.[] | select(.version == $version and .stable == true) |
      .files[] | select(.os == "linux" and .arch == $arch and .kind == "archive") |
      .sha256)') || {
    err "stable Go archive not found in official release metadata"
    return 1
  }
  if [[ ! "$checksum" =~ ^[[:xdigit:]]{64}$ ]]; then
    err "invalid Go archive checksum in release metadata"
    return 1
  fi
  printf '%s\n' "$checksum"
}

download_go() {
  local arch tmp checksum backup=/usr/local/go.psv-backup
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) err "unsupported Go archive architecture"; return 1 ;;
  esac
  if [[ -e /usr/local/go && -e "$backup" ]]; then
    err "$backup already exists; review and move it before replacing Go"
    return 1
  fi
  tmp=$(mktemp -d)
  log "downloading Go $GO_VERSION; on failure inspect temporary files at $tmp"
  curl -fsSL 'https://go.dev/dl/?mode=json&include=all' -o "$tmp/releases.json"
  checksum=$(go_archive_checksum "$GO_VERSION" "$arch" < "$tmp/releases.json")
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
    -o "$tmp/go.tar.gz"
  if ! printf '%s  %s\n' "$checksum" "$tmp/go.tar.gz" | sha256sum --check --status; then
    err "Go archive checksum mismatch; nothing installed; inspect $tmp"
    return 1
  fi
  tar -xzf "$tmp/go.tar.gz" -C "$tmp"
  if [[ -e /usr/local/go ]]; then
    sudo_ mv /usr/local/go "$backup"
    log "previous Go installation retained at $backup"
  fi
  if ! sudo_ mv "$tmp/go" /usr/local/go; then
    err "Go installation failed; inspect $tmp and restore $backup if present"
    return 1
  fi
  rm -- "$tmp/releases.json" "$tmp/go.tar.gz"
  rmdir -- "$tmp"
  log "installed: $(/usr/local/go/bin/go version)"
}

install_go() {
  local current
  current=$(installed_go_version) || {
    err "could not query the installed Go version"
    return 1
  }
  if version_at_least "$current" "$GO_VERSION"; then
    log "keeping installed Go $current (requested minimum $GO_VERSION)"
    return
  fi
  download_go
}

main() {
  local stage="${1:-core}"
  case "$stage" in
    -h|--help|help) usage; return ;;
    core|runtimes|bpf) ;;
    *) err "unknown stage: $stage"; usage >&2; return 2 ;;
  esac
  if (( $# > 1 )); then
    err "specify one setup stage at a time"
    return 2
  fi
  validate_go_version || return
  preflight || return
  apt_install ca-certificates curl jq build-essential
  install_go
  case "$stage" in
    runtimes) apt_install runc containerd ;;
    bpf) apt_install clang llvm libbpf-dev linux-tools-common linux-tools-generic ;;
  esac
  log "done: $stage"
  log 'ensure /usr/local/go/bin is on PATH: export PATH="/usr/local/go/bin:$PATH"'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
