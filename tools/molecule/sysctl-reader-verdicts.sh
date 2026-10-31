#!/usr/bin/env bash
# Record what the real sysctl readers of the Molecule images set for every case of the kernel parameter
# fixture (FREES-107, "the reader is the oracle"):
#   sysctl-reader-verdicts.sh <verified images record> <cases.json> <verdicts.json> <work directory>
# Each image runs in a throwaway container without a network. For every case the container empties the
# sysctl configuration directories and /etc/sysctl.conf, copies the case in, and runs systemd-sysctl with
# debug logging (where the image has it) and `sysctl --system --dry-run`. The container's /proc/sys is
# read-only, so no reader changes a kernel value; only what each reader tried to set is recorded.
set -euo pipefail

record="$1"
cases="$2"
verdicts="$3"
work="$4"

image_of() {
  local tag
  tag="$(sed -n "/^$1:\$/,/^[a-z_]*:\$/ s/^  tag: \"\\([0-9a-f-]*\\)\"\$/\\1/p" "${record}" | head -n 1)"
  if [[ -z "${tag}" ]]; then
    printf 'error: %s records no image for %s\n' "${record}" "$1" >&2
    exit 1
  fi
  printf 'freesecdev-molecule/%s:%s\n' "$1" "${tag}"
}

rm -rf "${work}"
mkdir -p "${work}/cases" "${work}/raw/ubuntu" "${work}/raw/rhel_compatible"
uv run --frozen python tools/molecule/sysctl_reader.py materialise "${cases}" "${work}/cases"

# shellcheck disable=SC2016 # expanded inside the container
inside='
set -u
for case in /cases/*/; do
  name="$(basename "${case}")"
  rm -rf /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /etc/sysctl.conf /srv
  mkdir -p /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d
  cp -a "${case}root/." /
  if [ -x /usr/lib/systemd/systemd-sysctl ]; then
    SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-sysctl > "/raw/${name}.systemd.log" 2>&1 || true
  fi
  sysctl --system --dry-run > "/raw/${name}.procps.log" 2>&1 || true
done
'
for platform in ubuntu rhel_compatible; do
  docker run --rm --network none --user root \
    -v "$(realpath "${work}/cases"):/cases:ro" -v "$(realpath "${work}/raw/${platform}"):/raw" \
    "$(image_of "${platform}")" bash -c "${inside}"
done
uv run --frozen python tools/molecule/sysctl_reader.py parse "${cases}" "${work}/raw" "${verdicts}"
