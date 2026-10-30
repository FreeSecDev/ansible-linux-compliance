#!/usr/bin/env bash
set -uo pipefail

readonly MARGIN_DAYS=7
readonly DATE='^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
readonly VERSION='^[0-9]+(\.[0-9]+)+$'

base_pins="${1:-}"
head_pins="${2:-}"
today="${3:-$(date -u +%F)}"

current() {
  printf 'current\n'
  exit 0
}

pin() {
  local file="$1" name="$2" pattern="$3" values
  [[ -f "${file}" && ! -L "${file}" ]] || return 1
  values="$(sed -n "s/^${name} := \\(.*\\)\$/\\1/p" "${file}")" || return 1
  [[ -n "${values}" && "${values}" != *$'\n'* && "${values}" =~ ${pattern} ]] || return 1
  printf '%s\n' "${values}"
}

valid_date() {
  [[ "$1" =~ ${DATE} ]] && [[ "$(date -u -d "$1" +%F 2>/dev/null)" == "$1" ]]
}

stopped() {
  local deadline
  valid_date "$1" || return 1
  deadline="$(date -u -d "$1 - ${MARGIN_DAYS} days" +%F)" || return 1
  [[ ! "${today}" < "${deadline}" ]]
}

valid_date "${today}" || current
base_version="$(pin "${base_pins}" SCC_VERSION "${VERSION}")" || current
head_version="$(pin "${head_pins}" SCC_VERSION "${VERSION}")" || current
base_expires="$(pin "${base_pins}" SCC_EXPIRES "${DATE}")" || current
head_expires="$(pin "${head_pins}" SCC_EXPIRES "${DATE}")" || current
[[ "${base_version}" == "${head_version}" ]] || current
cmp --silent -- "${base_pins}" "${head_pins}" || current
stopped "${base_expires}" || current
stopped "${head_expires}" || current
printf 'expired\n'
