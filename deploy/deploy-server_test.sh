#!/usr/bin/env bash
# Exercise deployment decisions without contacting the server.

set -euo pipefail

SCRIPT_DIR=""
if ! SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; then
  printf 'error: could not resolve the script directory\n' >&2
  exit 1
fi
readonly SCRIPT_DIR

# shellcheck source=deploy/deploy-server.sh
source "${SCRIPT_DIR}/deploy-server.sh"

fail() {
  printf 'FAIL: %s\n' "${1}" >&2
  return 1
}

queue_responses() {
  exec 9< <(printf '%s\n' "$@")
}

run_remote_status() {
  local command record status body
  command="${1}"
  printf '%s\n' "${command}" >>"${COMMAND_LOG}"

  if ! IFS= read -r record <&9; then
    fail "no queued response for ${command}"
    return 99
  fi
  status="${record%%|*}"
  body="${record#*|}"
  printf '%s' "${body}"
  return "${status}"
}

run_remote() {
  local command
  command="${1}"
  REMOTE_CALL_COUNT=$((REMOTE_CALL_COUNT + 1))
  printf '%s\n' "${command}" >>"${REMOTE_COMMAND_LOG}"

  if ((REMOTE_CALL_COUNT == REMOTE_FAIL_AT)); then
    return 1
  fi
  if [[ "${command}" == *"${LOCAL_HEALTH_URL}"* ]]; then
    printf 'ok\n'
  fi
  if [[ "${command}" == *"${LOCAL_INDEX_URL}"* ]]; then
    printf '<meta name="paper-version" content="%s">\n' \
      "${INSTALL_VERSION}"
  fi
}

rollback_server() {
  ROLLBACK_COUNT=$((ROLLBACK_COUNT + 1))
}

sleep() {
  :
}

assert_status() {
  local want label status
  want="${1}"
  label="${2}"
  shift 2

  status=0
  "$@" >/dev/null 2>&1 || status=$?
  if ((status != want)); then
    fail "${label}: got status ${status}, want ${want}"
  fi
}

assert_value() {
  local want got label
  want="${1}"
  got="${2}"
  label="${3}"
  if [[ "${got}" != "${want}" ]]; then
    fail "${label}: got ${got}, want ${want}"
  fi
}

assert_public_commands_are_bounded() {
  local command connect_flag request_flag
  connect_flag="--connect-timeout ${PUBLIC_CONNECT_TIMEOUT_SECONDS}"
  request_flag="--max-time ${PUBLIC_REQUEST_TIMEOUT_SECONDS}"
  if [[ ! -s "${COMMAND_LOG}" ]]; then
    fail "no public curl commands were recorded"
  fi

  while IFS= read -r command; do
    if [[ "${command}" != *"${connect_flag}"* ]]; then
      fail "public curl command has no connection timeout: ${command}"
    fi
    if [[ "${command}" != *"${request_flag}"* ]]; then
      fail "public curl command has no request timeout: ${command}"
    fi
  done <"${COMMAND_LOG}"
}

test_public_health_classification() {
  queue_responses "28|" "28|" "28|" "28|" "28|"
  assert_status 2 "unreachable health endpoint" check_public_server

  queue_responses "22|" "28|" "28|" "28|" "28|"
  assert_status 1 "answered health endpoint" check_public_server

  queue_responses "28|" "22|" "0|ok"
  assert_status 0 "eventually healthy endpoint" check_public_server
}

test_public_version_classification() {
  local version marker
  version="community-test-version"
  marker="<meta name=\"paper-version\" content=\"${version}\">"

  queue_responses \
    "0|<html>old version</html>" "28|" "28|" "28|" "28|"
  assert_status 1 "answered page with old version" \
    verify_public_version "${version}"

  queue_responses "28|" "22|" "0|${marker}"
  assert_status 0 "eventually current version" \
    verify_public_version "${version}"
}

reset_install_mocks() {
  REMOTE_CALL_COUNT=0
  REMOTE_FAIL_AT="${1}"
  ROLLBACK_COUNT=0
  INSTALL_VERSION="community-test-version"
  : >"${REMOTE_COMMAND_LOG}"
}

test_install_rolls_back_after_binary_promotion() {
  reset_install_mocks 4
  assert_status 1 "service promotion failure" \
    install_server "${INSTALL_VERSION}"
  assert_value 1 "${ROLLBACK_COUNT}" \
    "rollback count after service promotion failure"

  reset_install_mocks 5
  assert_status 1 "daemon reload failure" \
    install_server "${INSTALL_VERSION}"
  assert_value 1 "${ROLLBACK_COUNT}" \
    "rollback count after daemon reload failure"

  reset_install_mocks 0
  assert_status 0 "successful install" \
    install_server "${INSTALL_VERSION}"
  assert_value 0 "${ROLLBACK_COUNT}" \
    "rollback count after successful install"
}

main() {
  TEST_DIR="$(mktemp -d)"
  COMMAND_LOG="${TEST_DIR}/commands"
  REMOTE_COMMAND_LOG="${TEST_DIR}/remote-commands"
  trap \
    'rm -f "${COMMAND_LOG}" "${REMOTE_COMMAND_LOG}"; rmdir "${TEST_DIR}"' \
    EXIT
  : >"${COMMAND_LOG}"
  : >"${REMOTE_COMMAND_LOG}"

  test_public_health_classification
  test_public_version_classification
  assert_public_commands_are_bounded
  test_install_rolls_back_after_binary_promotion
  printf 'deploy-server tests passed\n'
}

main "$@"
