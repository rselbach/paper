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

main() {
  TEST_DIR="$(mktemp -d)"
  trap 'rm -f "${COMMAND_LOG}"; rmdir "${TEST_DIR}"' EXIT
  COMMAND_LOG="${TEST_DIR}/commands"
  : >"${COMMAND_LOG}"

  test_public_health_classification
  test_public_version_classification
  assert_public_commands_are_bounded
  printf 'deploy-server tests passed\n'
}

main "$@"
