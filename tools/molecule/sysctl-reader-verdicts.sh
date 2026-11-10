#!/usr/bin/env bash
# Record what the real sysctl readers of the Molecule images write for every case of the kernel parameter
# fixture (FREES-107, "the reader is the oracle"):
#   sysctl-reader-verdicts.sh <verified images record> <cases.json> <verdicts.json> <work directory>
# Each image runs in a throwaway container without a network, with every capability dropped but
# CAP_SYS_ADMIN and CAP_SETFCAP, and runs sysctl-reader-inside.sh. That script refuses to go on
# unless /proc/sys is Docker's read-only proc mount, enters a user and mount namespace of its own,
# where the read-only flags of Docker's mounts are locked, and mounts a private tmpfs over /proc/sys
# there, which it checks before any reader runs; so no reader and no remount can reach a kernel
# parameter of the host. The tmpfs holds every parameter of the cases, preset to 9; for every case
# the container empties the configuration directories and removes /etc/sysctl.conf and ufw's
# configuration, copies the case in, resets the tree, runs one reader (systemd-sysctl, where the
# image has it, or `sysctl --system`) and records the files of the tree as base64. The parser reads
# the values back from those files, not from the readers' output.
set -euo pipefail

record="$1"
cases="$2"
verdicts="$3"
work="$4"
inside="$(dirname "$0")/sysctl-reader-inside.sh"

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
chmod a+rwx "${work}/raw/ubuntu" "${work}/raw/rhel_compatible"
uv run --frozen python tools/molecule/sysctl_reader.py materialise "${cases}" "${work}/cases"

for platform in ubuntu rhel_compatible; do
  docker run --rm --network none --cap-drop ALL --cap-add SYS_ADMIN --cap-add SETFCAP \
    --security-opt no-new-privileges -v "$(realpath "${work}/cases"):/cases:ro" \
    -v "$(realpath "${work}/raw/${platform}"):/raw" -v "$(realpath "${inside}"):/oracle.sh:ro" \
    "$(image_of "${platform}")" bash /oracle.sh
done
uv run --frozen python tools/molecule/sysctl_reader.py parse "${cases}" "${work}/raw" "${verdicts}"
