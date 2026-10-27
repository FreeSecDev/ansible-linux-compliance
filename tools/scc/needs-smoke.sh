#!/usr/bin/env bash
set -uo pipefail

readonly SCC_PATHS='^(extensions/ci/scc/|tools/scc/|tools/lint/fetch-hadolint\.sh$|Makefile$|\.github/workflows/|tests/unit/tools/test_scc_image\.py$|plugins/module_utils/compliance/(scc|process|backends)[^/]*\.py$|tools/reporting/(checklist|stig_content)[^/]*\.py$|tests/.*scc|docs/adr/00(19|20)-)'
readonly SHA='^[0-9a-f]{40}$'

event="${1:-}"
base="${2:-}"
head="${3:-}"

run_smoke() {
  printf 'true\n'
  exit 0
}

case "${event}" in
  pull_request)
    if [[ -z "${head}" ]]; then
      head='HEAD'
    elif [[ ! "${head}" =~ ${SHA} ]]; then
      run_smoke
    fi
    ;;
  merge_group)
    [[ "${head}" =~ ${SHA} ]] || run_smoke
    ;;
  *)
    run_smoke
    ;;
esac
[[ "${base}" =~ ${SHA} ]] || run_smoke

if ! changed="$(git diff --no-renames --name-only "${base}" "${head}" -- 2>/dev/null)"; then
  run_smoke
fi
if grep -qE "${SCC_PATHS}" <<<"${changed}"; then
  printf 'true\n'
else
  printf 'false\n'
fi
