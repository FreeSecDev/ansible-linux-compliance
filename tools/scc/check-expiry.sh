#!/usr/bin/env bash
set -euo pipefail

readonly MARGIN_DAYS=7

expires="${1:?usage: check-expiry.sh <SCC_EXPIRES as YYYY-MM-DD> [today as YYYY-MM-DD]}"
today="${2:-$(date -u +%F)}"

for value in "${expires}" "${today}"; do
  if [[ ! "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || ! date -u -d "${value}" +%F >/dev/null 2>&1; then
    printf 'error: %s is not a date in the form YYYY-MM-DD\n' "${value}" >&2
    exit 2
  fi
done

deadline="$(date -u -d "${expires} - ${MARGIN_DAYS} days" +%F)"
if [[ ! "${today}" < "${deadline}" ]]; then
  printf 'error: the pinned SCC release expires on %s; from %s on SCC is not built or run.\n' "${expires}" "${deadline}" >&2
  printf 'Bump the SCC pin and SCC_EXPIRES in extensions/ci/scc/scc.pins (ADR 0019, decision 7).\n' >&2
  exit 1
fi
printf 'the pinned SCC release expires on %s; it may be built and run before %s\n' "${expires}" "${deadline}"
