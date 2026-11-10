#!/usr/bin/env bash
set -euo pipefail

usage='usage: bash tools/lint/sshd_readers.sh <Ubuntu 24.04 Molecule image> <Rocky Linux 9 Molecule image>'
ubuntu_image="${1:?${usage}}"
rocky_image="${2:?${usage}}"
repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixtures="${repository}/tests/fixtures/sshd_readers"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cd "${repository}"
PYTHONPATH="${repository}/build/collections" uv run --frozen python -m tools.lint.sshd_readers \
  prepare "${fixtures}/cases.json" "${work}/cases"

run_reader() {
  local image="$1"
  shift
  docker run --rm --network none --user 0 \
    -v "${work}/cases:/cases:ro" -v "${repository}/tools/lint:/src/tools/lint:ro" \
    "${image}" "$@"
}

run_reader "${ubuntu_image}" sh /src/tools/lint/sshd_readers_probe.sh /cases >"${work}/ubuntu.tsv"
run_reader "${rocky_image}" sh /src/tools/lint/sshd_readers_probe.sh /cases >"${work}/rocky.tsv"
PYTHONPATH="${repository}/build/collections" uv run --frozen python -m tools.lint.sshd_readers \
  merge "${work}" "${fixtures}/verdicts.json"
