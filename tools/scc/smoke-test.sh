#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-test.sh <local image tag> <expected SCC version>}"
expected_version="${2:?usage: smoke-test.sh <local image tag> <expected SCC version>}"

if [[ ! "${image}" =~ ^localhost/[a-z0-9._/-]+:[A-Za-z0-9._-]+$ ]]; then
  printf 'error: the SCC image must carry a localhost/ tag, so it cannot name a registry\n' >&2
  exit 2
fi

run_cscc() {
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m "${image}" "$@"
}

status=0
output="$(run_cscc --version 2>&1)" || status=$?
printf 'cscc --version (exit status %s):\n%s\n' "${status}" "${output}"
if [[ "${status}" != '0' ]]; then
  printf 'error: cscc --version exited with status %s\n' "${status}" >&2
  exit 1
fi
if ! grep -qE "(^|[^0-9.])${expected_version//./\\.}([^0-9.]|$)" <<<"${output}"; then
  printf 'error: cscc --version does not report SCC %s\n' "${expected_version}" >&2
  exit 1
fi
printf 'SCC %s starts in %s and reports its version\n' "${expected_version}" "${image}"
