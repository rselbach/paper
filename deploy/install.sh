#!/usr/bin/env bash
#
# Build paper, stop the systemd service, install the binary to
# /usr/local/bin, then start the service again.
#
# Run on the target Linux server from the repo root (or anywhere — the
# script cd's to its own repo root).

set -euo pipefail

readonly SERVICE_NAME="paper"
readonly BINARY_NAME="paper"
readonly INSTALL_DIR="/usr/local/bin"
readonly INSTALL_PATH="${INSTALL_DIR}/${BINARY_NAME}"

err() {
  echo "install.sh: $*" >&2
}

die() {
  err "$*"
  exit 1
}

sudo_run() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

build_version() {
  if command -v git >/dev/null 2>&1 \
      && git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
      && [[ -z "$(git status --porcelain)" ]]; then
    git rev-parse HEAD
  else
    printf 'dev\n'
  fi
}

build() {
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  cd "${repo_root}"

  command -v go >/dev/null 2>&1 || die "go is not installed or not in PATH"

  local build_dir
  build_dir="$(mktemp -d)"
  BUILD_DIR="${build_dir}"

  local version
  version="$(build_version)"

  echo "Building ${BINARY_NAME} ${version} in ${repo_root}..."
  if ! CGO_ENABLED=0 go build -ldflags "-X main.version=${version}" -o "${build_dir}/${BINARY_NAME}" .; then
    die "go build failed"
  fi
}

stop_service() {
  if ! sudo_run systemctl list-unit-files "${SERVICE_NAME}.service" \
      >/dev/null 2>&1; then
    err "warning: ${SERVICE_NAME}.service not found; skipping stop"
    return 0
  fi

  if sudo_run systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    echo "Stopping ${SERVICE_NAME}.service..."
    sudo_run systemctl stop "${SERVICE_NAME}.service"
  else
    echo "${SERVICE_NAME}.service is not running; nothing to stop."
  fi
}

install_binary() {
  echo "Installing binary to ${INSTALL_PATH}..."
  sudo_run install -m 0755 "${BUILD_DIR}/${BINARY_NAME}" "${INSTALL_PATH}"
}

start_service() {
  echo "Starting ${SERVICE_NAME}.service..."
  sudo_run systemctl start "${SERVICE_NAME}.service"

  if ! sudo_run systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    sudo_run systemctl --no-pager status "${SERVICE_NAME}.service" >&2 || true
    die "${SERVICE_NAME}.service failed to start"
  fi

  echo "${SERVICE_NAME}.service is running."
}

cleanup() {
  if [[ -n "${BUILD_DIR:-}" && -d "${BUILD_DIR}" ]]; then
    rm -rf "${BUILD_DIR}"
  fi
}

main() {
  BUILD_DIR=""
  trap cleanup EXIT

  build
  stop_service
  install_binary
  start_service

  echo "Done."
}

main "$@"
