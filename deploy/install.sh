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
readonly STAGED_PATH="${INSTALL_PATH}.next"
readonly BACKUP_PATH="${INSTALL_PATH}.previous"

SERVICE_WAS_ACTIVE=false
HAD_INSTALLED_BINARY=false
STAGED_BINARY=false

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
    SERVICE_WAS_ACTIVE=true
    echo "Stopping ${SERVICE_NAME}.service..."
    if ! sudo_run systemctl stop "${SERVICE_NAME}.service"; then
      return 1
    fi
  else
    echo "${SERVICE_NAME}.service is not running; nothing to stop."
  fi
}

stage_binary() {
  echo "Staging binary at ${STAGED_PATH}..."
  STAGED_BINARY=true
  sudo_run install -m 0755 "${BUILD_DIR}/${BINARY_NAME}" "${STAGED_PATH}"
}

backup_binary() {
  if [[ ! -f "${INSTALL_PATH}" ]]; then
    return 0
  fi

  sudo_run cp -a "${INSTALL_PATH}" "${BACKUP_PATH}"
  HAD_INSTALLED_BINARY=true
}

promote_binary() {
  echo "Installing binary to ${INSTALL_PATH}..."
  if ! sudo_run mv "${STAGED_PATH}" "${INSTALL_PATH}"; then
    return 1
  fi
  STAGED_BINARY=false
}

start_service() {
  echo "Starting ${SERVICE_NAME}.service..."
  if ! sudo_run systemctl start "${SERVICE_NAME}.service"; then
    return 1
  fi

  if ! sudo_run systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    sudo_run systemctl --no-pager status "${SERVICE_NAME}.service" >&2 || true
    err "${SERVICE_NAME}.service failed to start"
    return 1
  fi

  echo "${SERVICE_NAME}.service is running."
}

rollback_binary() {
  err "restoring the previous installation"
  if [[ "${HAD_INSTALLED_BINARY}" == true ]]; then
    if ! sudo_run install -m 0755 "${BACKUP_PATH}" "${INSTALL_PATH}"; then
      return 1
    fi
  else
    if ! sudo_run rm -f "${INSTALL_PATH}"; then
      return 1
    fi
  fi

  if [[ "${SERVICE_WAS_ACTIVE}" == true ]]; then
    if ! sudo_run systemctl restart "${SERVICE_NAME}.service"; then
      return 1
    fi
  fi
  return 0
}

cleanup() {
  if [[ -n "${BUILD_DIR:-}" && -d "${BUILD_DIR}" ]]; then
    rm -rf "${BUILD_DIR}"
  fi
  if [[ "${STAGED_BINARY}" == true ]]; then
    sudo_run rm -f "${STAGED_PATH}"
  fi
}

main() {
  BUILD_DIR=""
  trap cleanup EXIT

  build
  stage_binary
  backup_binary
  if ! stop_service; then
    die "could not stop ${SERVICE_NAME}.service"
  fi
  if ! promote_binary; then
    rollback_binary || err "could not restore the previous installation"
    die "could not install ${BINARY_NAME}"
  fi
  if ! start_service; then
    rollback_binary || err "could not restore the previous installation"
    die "could not start ${SERVICE_NAME}.service"
  fi

  echo "Done."
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
