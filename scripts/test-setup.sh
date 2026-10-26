#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

unset GO_VERSION
. "$(dirname "${BASH_SOURCE[0]}")/../setup.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ "$GO_VERSION" == 1.26.10 ]] || fail "unexpected installer default"
[[ "$MIN_GO_VERSION" == 1.24.0 ]] || fail "unexpected Go minimum"
version_at_least "$GO_VERSION" "$MIN_GO_VERSION" || fail "default below module minimum"
for version in 1.24.0 1.24.9 1.26.10 1.27.3; do
  GO_VERSION="$version" validate_go_version || fail "rejected valid version $version"
done
for version in '' invalid 1.23.4 1.24 1.26.0rc1; do
  if GO_VERSION="$version" validate_go_version 2>/dev/null; then
    fail "accepted invalid/unsupported version $version"
  fi
done
if version_at_least 1.9.0 1.24.0; then fail "version comparison is lexical"; fi
if version_at_least broken 1.24.0; then fail "accepted malformed installed version"; fi

log() { :; }
downloaded=0
download_go() { downloaded=$((downloaded + 1)); }
installed_go_version() { printf '%s\n' "$existing_version"; }
for existing_version in 1.24.0 1.26.10 1.27.3 0.0.0; do
  downloaded=0
  install_go
  case "$existing_version" in
    1.24.0|0.0.0) [[ $downloaded == 1 ]] || fail "older/missing Go not installed" ;;
    *) [[ $downloaded == 0 ]] || fail "current/newer Go replaced" ;;
  esac
done
installed_go_version() { return 1; }
if install_go 2>/dev/null; then fail "Go version query failure hidden"; fi

checksum=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
metadata='[{"version":"go1.26.10","stable":true,"files":[
  {"os":"linux","arch":"amd64","kind":"archive","sha256":"'"$checksum"'"},
  {"os":"linux","arch":"arm64","kind":"archive","sha256":"invalid"}]}]'
[[ "$(printf '%s' "$metadata" | go_archive_checksum 1.26.10 amd64)" == "$checksum" ]] \
  || fail "wrong checksum selected"
if printf '%s' "$metadata" | go_archive_checksum 1.26.10 arm64 2>/dev/null; then
  fail "malformed checksum accepted"
fi
if printf '%s' "$metadata" | go_archive_checksum 1.25.0 amd64 2>/dev/null; then
  fail "missing archive accepted"
fi
if printf 'invalid-json' | go_archive_checksum 1.26.10 amd64 2>/dev/null; then
  fail "malformed metadata accepted"
fi

calls=()
preflight() { calls+=("preflight"); }
apt_install() { calls+=("apt:$*"); }
install_go() { calls+=("go"); }
main --help >/dev/null
[[ ${#calls[@]} == 0 ]] || fail "help had side effects"
for stage in core runtimes bpf; do
  calls=()
  main "$stage"
  [[ "${calls[0]}" == preflight ]] || fail "preflight not called first"
  [[ "${calls[1]}" == 'apt:ca-certificates curl jq build-essential' ]] \
    || fail "wrong core packages"
  [[ "${calls[2]}" == go ]] || fail "Go setup missing"
  case "$stage" in
    core) [[ ${#calls[@]} == 3 ]] || fail "unexpected core side effects" ;;
    runtimes) [[ "${calls[3]}" == 'apt:runc containerd' ]] || fail "wrong runtime packages" ;;
    bpf) [[ "${calls[3]}" == 'apt:clang llvm libbpf-dev linux-tools-common linux-tools-generic' ]] \
      || fail "wrong BPF packages" ;;
  esac
done
if (main invalid) >/dev/null 2>&1; then fail "unknown stage accepted"; fi
if (main core runtimes) >/dev/null 2>&1; then fail "multiple stages accepted"; fi
calls=()
if GO_VERSION=1.23.4 main core >/dev/null 2>&1; then fail "old Go override accepted"; fi
[[ ${#calls[@]} == 0 ]] || fail "invalid override changed host state"
preflight() { return 1; }
if main core >/dev/null 2>&1; then fail "preflight failure hidden"; fi
[[ ${#calls[@]} == 0 ]] || fail "failed preflight changed host state"
printf 'Setup unit tests passed (no host changes).\n'
