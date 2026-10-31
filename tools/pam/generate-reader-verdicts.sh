#!/usr/bin/env bash
set -euo pipefail

usage='usage: generate-reader-verdicts.sh <platform>=<verified image id> ... (from make molecule-images-ids)'
if [[ $# -eq 0 ]]; then
  printf 'error: %s\n' "${usage}" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="${root}/build/pam-reader-verdicts"
rm -rf -- "${work}"
mkdir -p -- "${work}/out"

python -m tools.pam.reader_corpus cases --out "${work}/cases"

for pair in "$@"; do
  if [[ ! "${pair}" =~ ^([a-z][a-z0-9_]*)=(sha256:[0-9a-f]{64})$ ]]; then
    printf 'error: %s is not <platform>=<image id>; %s\n' "${pair}" "${usage}" >&2
    exit 2
  fi
  platform="${BASH_REMATCH[1]}"
  image="${BASH_REMATCH[2]}"
  printf 'probing the pam readers of %s (%s)\n' "${platform}" "${image}"
  docker run --rm --pull never \
    -v "${work}/cases:/cases:ro" \
    -v "${root}/tools/pam/oracle:/oracle:ro" \
    -v "${work}/out:/out" \
    "${image}" bash /oracle/probe-in-image.sh
done

python -m tools.pam.reader_corpus assemble --outputs "${work}/out" --table "${root}/tests/fixtures/pam_conf/reader_verdicts.json"
