#!/usr/bin/env bash
set -euo pipefail

usage='usage: bash tools/lint/login_defs_readers.sh <Ubuntu 24.04 Molecule image> <Rocky Linux 9 Molecule image>'
ubuntu_image="${1:?${usage}}"
rocky_image="${2:?${usage}}"
repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixtures="${repository}/tests/fixtures/login_defs_readers"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cd "${repository}"
uv run --frozen python -m tools.lint.login_defs_readers decide "${fixtures}/cases.json" "${work}/decisions.json" \
  >/dev/null
uv run --frozen python -m tools.lint.login_defs_readers prepare "${fixtures}/cases.json" "${work}/decisions.json" \
  "${work}/states"

run_reader() {
  local image="$1"
  shift
  docker run --rm --network none --user 0 \
    -v "${work}/states:/states:ro" -v "${repository}/tools/lint:/src/tools/lint:ro" \
    "${image}" "$@"
}

run_reader "${ubuntu_image}" sh /src/tools/lint/login_defs_readers_shadow.sh /states /src/tools/lint >"${work}/states/ubuntu-shadow.tsv"
run_reader "${rocky_image}" sh /src/tools/lint/login_defs_readers_shadow.sh /states /src/tools/lint >"${work}/states/rocky-shadow.tsv"
run_reader "${rocky_image}" python3 /src/tools/lint/login_defs_readers.py econf /states >"${work}/states/rocky-econf.json"
uv run --frozen python -m tools.lint.login_defs_readers merge "${work}/states" "${fixtures}/verdicts.json"
