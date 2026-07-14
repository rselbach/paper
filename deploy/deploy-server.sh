#!/usr/bin/env bash
# Cross-compile Paper locally, deploy it to ssh.rselbach.com, and verify it.

set -euo pipefail

readonly SSH_TARGET="ssh.rselbach.com"
readonly SERVICE="paper.service"
readonly LOCAL_ARTIFACT="/tmp/paper-linux-amd64"
readonly REMOTE_ARTIFACT="/data/home/rselbach/paper-linux-amd64"
readonly REMOTE_BINARY="/usr/local/bin/paper"
readonly REMOTE_DATABASE="/data/home/paper/paper.db"
readonly LOCAL_HEALTH_URL="http://127.0.0.1:11432/healthz"
readonly LOCAL_INDEX_URL="http://127.0.0.1:11432/"
readonly PUBLIC_HEALTH_URL="https://paper.rselbach.com/healthz"
readonly PUBLIC_INDEX_URL="https://paper.rselbach.com/"
readonly -a SSH_OPTIONS=(
  -o BatchMode=yes
  -o ConnectTimeout=10
)

usage() {
  printf 'Usage: %s {check|deploy}\n' "${0##*/}" >&2
}

run_remote() {
  local command
  command="${1}"

  # The command is assembled locally from script constants.
  # shellcheck disable=SC2029
  if ! ssh "${SSH_OPTIONS[@]}" "${SSH_TARGET}" "${command}"; then
    printf 'error: remote command failed: %s\n' "${command}" >&2
    return 1
  fi
}

check_local_server() {
  printf 'Service: '
  run_remote "systemctl is-active ${SERVICE}"

  printf 'Local health: '
  run_remote \
    "curl --fail --silent --show-error ${LOCAL_HEALTH_URL}"
}

check_public_server() {
  printf 'Public health: '
  run_remote \
    "curl --fail --silent --show-error ${PUBLIC_HEALTH_URL}"
}

check_server() {
  check_local_server
  check_public_server
}

require_clean_worktree() {
  local status
  if ! status="$(git status --porcelain)"; then
    printf 'error: could not inspect the Git worktree\n' >&2
    return 1
  fi
  if [[ -z "${status}" ]]; then
    return 0
  fi

  printf 'error: refusing to deploy a dirty worktree:\n%s\n' \
    "${status}" >&2
  return 1
}

current_version() {
  local version
  if ! version="$(git rev-parse HEAD)"; then
    printf 'error: could not read the Git commit\n' >&2
    return 1
  fi
  printf '%s\n' "${version}"
}

build_server() {
  local version
  version="${1}"

  if ! just check; then
    printf 'error: checks failed\n' >&2
    return 1
  fi

  local -a build_command=(
    go build
    -trimpath
    -ldflags "-X main.version=${version}"
    -o "${LOCAL_ARTIFACT}"
    .
  )
  if ! env \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    "${build_command[@]}"; then
    printf 'error: Linux build failed\n' >&2
    return 1
  fi
}

upload_server() {
  if ! scp \
    "${SSH_OPTIONS[@]}" \
    "${LOCAL_ARTIFACT}" \
    "${SSH_TARGET}:${REMOTE_ARTIFACT}"; then
    printf 'error: upload failed\n' >&2
    return 1
  fi
}

verify_upload() {
  local local_line
  local remote_line
  if ! local_line="$(shasum -a 256 "${LOCAL_ARTIFACT}")"; then
    printf 'error: local checksum failed\n' >&2
    return 1
  fi
  if ! remote_line="$(run_remote \
    "sha256sum ${REMOTE_ARTIFACT}")"; then
    printf 'error: remote checksum failed\n' >&2
    return 1
  fi

  local local_checksum
  local remote_checksum
  local_checksum="${local_line%% *}"
  remote_checksum="${remote_line%% *}"
  if [[ "${local_checksum}" == "${remote_checksum}" ]]; then
    printf 'Upload checksum: %s\n' "${local_checksum}"
    return 0
  fi

  printf 'error: checksum mismatch: local=%s remote=%s\n' \
    "${local_checksum}" "${remote_checksum}" >&2
  return 1
}

backup_server() {
  run_remote \
    "sudo cp -a ${REMOTE_BINARY} ${REMOTE_BINARY}.previous"

  local backup_command
  backup_command="sudo -u paper sqlite3 ${REMOTE_DATABASE}"
  backup_command+=" \".backup '${REMOTE_DATABASE}.previous'\""
  run_remote "${backup_command}"
}

verify_local_version() {
  local version
  version="${1}"

  local index
  if ! index="$(run_remote \
    "curl --fail --silent --show-error ${LOCAL_INDEX_URL}")"; then
    printf 'error: could not read the local Paper page\n' >&2
    return 1
  fi

  local marker
  marker="<meta name=\"paper-version\" content=\"${version}\">"
  if [[ "${index}" == *"${marker}"* ]]; then
    printf 'Local version: %s\n' "${version}"
    return 0
  fi

  printf 'error: local page does not report version %s\n' \
    "${version}" >&2
  return 1
}

verify_public_version() {
  local version
  version="${1}"

  local index
  if ! index="$(curl --fail --silent --show-error \
    "${PUBLIC_INDEX_URL}")"; then
    printf 'error: could not read the public Paper page\n' >&2
    return 1
  fi

  local marker
  marker="<meta name=\"paper-version\" content=\"${version}\">"
  if [[ "${index}" == *"${marker}"* ]]; then
    printf 'Public version: %s\n' "${version}"
    return 0
  fi

  printf 'error: public page does not report version %s\n' \
    "${version}" >&2
  return 1
}

rollback_server() {
  printf 'Rolling back to the previous binary...\n' >&2
  local rollback_command
  rollback_command="sudo install -o root -g root -m 0755"
  rollback_command+=" ${REMOTE_BINARY}.previous ${REMOTE_BINARY}"
  if ! run_remote "${rollback_command}"; then
    printf 'error: binary rollback failed\n' >&2
    return 1
  fi
  if ! run_remote "sudo systemctl restart ${SERVICE}"; then
    printf 'error: service restart after rollback failed\n' >&2
    return 1
  fi
  if ! check_local_server; then
    printf 'error: rolled-back service is unhealthy\n' >&2
    return 1
  fi
}

install_server() {
  local version
  version="${1}"

  local install_command
  install_command="sudo install -o root -g root -m 0755"
  install_command+=" ${REMOTE_ARTIFACT} ${REMOTE_BINARY}.next"
  run_remote "${install_command}"
  run_remote "sudo mv ${REMOTE_BINARY}.next ${REMOTE_BINARY}"

  if ! run_remote "sudo systemctl restart ${SERVICE}"; then
    printf 'error: service restart failed\n' >&2
    rollback_server
    return 1
  fi
  if ! check_local_server; then
    printf 'error: deployed service is unhealthy\n' >&2
    rollback_server
    return 1
  fi
  if ! verify_local_version "${version}"; then
    rollback_server
    return 1
  fi
}

deploy_server() {
  #require_clean_worktree

  local version
  if ! version="$(current_version)"; then
    return 1
  fi

  printf 'Building Paper %s for linux/amd64...\n' "${version}"
  build_server "${version}"
  upload_server
  verify_upload
  backup_server
  install_server "${version}"
  if ! check_public_server; then
    printf '%s\n' \
      'error: local deployment is healthy; public health failed' >&2
    return 1
  fi
  if ! verify_public_version "${version}"; then
    printf '%s\n' \
      'error: local deployment is healthy; public version failed' >&2
    return 1
  fi
  printf 'Deployed Paper %s.\n' "${version}"
}

main() {
  if (($# != 1)); then
    usage
    return 2
  fi

  local script_dir
  if ! script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" &&
    pwd)"; then
    printf 'error: could not resolve the script directory\n' >&2
    return 1
  fi
  if ! cd "${script_dir}/.."; then
    printf 'error: could not enter the repository root\n' >&2
    return 1
  fi

  case "${1}" in
  check)
    check_server
    ;;
  deploy)
    deploy_server
    ;;
  *)
    usage
    return 2
    ;;
  esac
}

main "$@"
