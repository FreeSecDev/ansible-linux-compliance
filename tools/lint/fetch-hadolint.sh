#!/usr/bin/env bash
set -euo pipefail

readonly HADOLINT_VERSION='2.15.1'
readonly HADOLINT_SHA256='c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507'
readonly HADOLINT_URL="https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-x86_64"

target="${1:?usage: fetch-hadolint.sh <binary path>}"

if [[ "$(uname -s)" != 'Linux' || "$(uname -m)" != 'x86_64' ]]; then
  printf 'error: the pinned hadolint binary is the Linux x86_64 build\n' >&2
  exit 1
fi

verified() {
  [[ -f "$1" && ! -L "$1" ]] && printf '%s  %s\n' "${HADOLINT_SHA256}" "$1" | sha256sum --check --strict --quiet
}

if verified "${target}"; then
  exit 0
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --max-filesize 67108864 --retry 3 --retry-all-errors --output "${work_dir}/hadolint" "${HADOLINT_URL}"
if ! verified "${work_dir}/hadolint"; then
  printf 'error: hadolint %s does not match the pinned SHA-256\n' "${HADOLINT_VERSION}" >&2
  exit 1
fi
mkdir -p "$(dirname "${target}")"
install -m 0755 "${work_dir}/hadolint" "${target}"
installed="$("${target}" --version)"
if [[ "${installed}" != *"${HADOLINT_VERSION}"* ]]; then
  printf 'error: expected hadolint %s, found %s\n' "${HADOLINT_VERSION}" "${installed}" >&2
  exit 1
fi
printf 'installed %s to %s\n' "${installed}" "${target}"
