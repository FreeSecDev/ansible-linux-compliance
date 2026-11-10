#!/usr/bin/env bash
set -euo pipefail

usage='usage: bash tools/lint/pwquality_readers.sh <Ubuntu 24.04 Molecule image> <Rocky Linux 9 Molecule image>'
ubuntu_image="${1:?${usage}}"
rocky_image="${2:?${usage}}"
repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixtures="${repository}/tests/fixtures/pwquality_readers"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cd "${repository}"
PYTHONPATH="${repository}/build/collections" uv run --frozen python -m tools.lint.pwquality_readers \
  prepare "${fixtures}/cases.json" "${work}"

run_reader() {
  local image="$1"
  shift
  docker run --rm --network none --user 0 \
    -v "${work}:/states:ro" -v "${repository}/tools/lint:/src/tools/lint:ro" \
    "${image}" "$@"
}

run_reader "${ubuntu_image}" dpkg-query -W libpwquality1 >"${work}/ubuntu.version"
run_reader "${rocky_image}" rpm -q libpwquality >"${work}/rocky.version"
run_reader "${ubuntu_image}" python3 -I /src/tools/lint/pwquality_readers_probe.py /states/states.json \
  >"${work}/ubuntu.json"
run_reader "${rocky_image}" python3 -I /src/tools/lint/pwquality_readers_probe.py /states/states.json \
  >"${work}/rocky.json"
PYTHONPATH="${repository}/build/collections" uv run --frozen python -m tools.lint.pwquality_readers \
  merge "${work}" "${fixtures}/verdicts.json"
