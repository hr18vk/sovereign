#!/usr/bin/env bash
# Supremum Engine — single-binary installer.
#
# Detects OS+arch, fetches the matching statically-linked binary, drops it on
# PATH. Under a second of wall time; zero build toolchain, zero config. The
# binary has no runtime dependencies (CGO_ENABLED=0, no glibc pin).
#
#   curl -fsSL https://raw.githubusercontent.com/hr18vk/sovereign/main/scripts/install.sh | bash
#
# This script deliberately does not run the engine: it installs it. Booting the
# crucible benchmark is scripts/benchmark.sh. The two are separate because a
# planetary-scale engine that auto-starts on install is a footgun, not a feature.

set -euo pipefail

readonly REPO="${SUPREMUM_REPO:-hr18vk/sovereign}"
readonly BASE="${SUPREMUM_BASE_URL:-https://github.com/${REPO}/releases/latest/download}"
readonly INSTALL_DIR="${SUPREMUM_INSTALL_DIR:-${SUPREMUM_INSTALL_DIR:-${HOME}/.sovereign/bin}}"

err()  { printf '\033[31msovereign: %s\033[0m\n' "$*" >&2; }
log()  { printf '\033[2msovereign: %s\033[0m\n' "$*"; }

require() { command -v "$1" >/dev/null 2>&1 || { err "missing required command: $1"; exit 1; }; }

detect_os() {
  case "$(uname -s)" in
    Linux)  printf 'linux'   ;;
    Darwin) printf 'darwin'  ;;
    *)      err "unsupported OS: $(uname -s)"; exit 1 ;;
  esac
}

# Graviton (arm64) is the recorded/supported target for the 57.63M ops/s
# measurement. amd64 binary exists for dev/iteration only.
detect_arch() {
  case "$(uname -m)" in
    aarch64|arm64) printf 'arm64' ;;
    x86_64|amd64)   printf 'amd64' ;;
    *)              err "unsupported arch: $(uname -m)"; exit 1 ;;
  esac
}

main() {
  require curl
  require mkdir
  require tar

  local os arch version asset url
  os="$(detect_os)"
  arch="$(detect_arch)"
  version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
  [ -n "${version}" ] || { err "could not resolve latest release tag"; exit 1; }

  asset="sovereign-${os}-${arch}"
  url="${BASE}/${asset}"

  log "installing sovereign ${version} (${os}/${arch}) -> ${INSTALL_DIR}"
  mkdir -p "${INSTALL_DIR}"

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT

  curl -fsSL --retry 3 --retry-connrefused --connect-timeout 10 \
       -o "${tmp}/sovereign" "${url}"
  chmod 0755 "${tmp}/sovereign"

  install -m 0755 "${tmp}/sovereign" "${INSTALL_DIR}/sovereign"

  log "installed: ${INSTALL_DIR}/sovereign"
  if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
    log "add to PATH:  export PATH=\"${INSTALL_DIR}:\$PATH\""
  fi
  log "verify:       sovereign --version"
  log "crucible:     ./scripts/benchmark.sh --core-count=32"
}

main "$@"
