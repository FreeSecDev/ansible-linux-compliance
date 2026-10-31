#!/usr/bin/env bash
# Record what the real sysctl readers of the Molecule images write for every case of the kernel parameter
# fixture (FREES-107, "the reader is the oracle"):
#   sysctl-reader-verdicts.sh <verified images record> <cases.json> <verdicts.json> <work directory>
# Each image runs in a throwaway container without a network, with every capability dropped but
# CAP_SYS_ADMIN, which mounts a private tmpfs over /proc/sys in the container's own mount namespace.
# The container refuses to go on unless /proc/sys was Docker's read-only proc mount before and is that
# tmpfs afterwards, so no reader can reach a kernel parameter of the host. The tmpfs holds every
# parameter of the cases, preset to 9; for every case the container empties the configuration
# directories and removes /etc/sysctl.conf, copies the case in, resets the tree, runs one reader
# (systemd-sysctl, where the image has it, or `sysctl --system`) and records the files of the tree as
# base64. The parser reads the values back from those files, not from the readers' output.
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
chmod a+rwx "${work}/raw/ubuntu" "${work}/raw/rhel_compatible"
uv run --frozen python tools/molecule/sysctl_reader.py materialise "${cases}" "${work}/cases"

# shellcheck disable=SC2016 # expanded inside the container
inside='
set -eu
options="$(grep " /proc/sys " /proc/self/mountinfo | head -n 1 | cut -d" " -f6)"
case ",${options}," in
  *,ro,*) ;;
  *) echo "error: /proc/sys is not read-only before the tmpfs is mounted; nothing ran" >&2; exit 3 ;;
esac
mount -t tmpfs -o size=4m,mode=755 freesecdev-sysctl-oracle /proc/sys
if [ "$(stat -f -c %T /proc/sys)" != tmpfs ]; then
  echo "error: /proc/sys is not the private tmpfs; nothing ran" >&2
  exit 3
fi
reset_tree() {
  while IFS= read -r parameter; do
    mkdir -p "/proc/sys/$(dirname "${parameter}")"
    printf "9\n" > "/proc/sys/${parameter}"
  done < /cases/proc.list
}
record_tree() {
  while IFS= read -r parameter; do
    printf "%s\t%s\n" "${parameter}" "$(base64 -w 0 "/proc/sys/${parameter}")"
  done < /cases/proc.list
}
for case in /cases/*/; do
  name="$(basename "${case}")"
  mkdir -p /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /srv
  find /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /srv -mindepth 1 -delete
  rm -f /etc/sysctl.conf
  cp -RP --preserve=mode,links "${case}root/." /
  if [ -x /usr/lib/systemd/systemd-sysctl ]; then
    reset_tree
    /usr/lib/systemd/systemd-sysctl > /dev/null 2>&1 || true
    record_tree > "/raw/${name}.systemd.values"
  fi
  reset_tree
  sysctl --system > /dev/null 2>&1 || true
  record_tree > "/raw/${name}.procps.values"
done
'
for platform in ubuntu rhel_compatible; do
  docker run --rm --network none --cap-drop ALL --cap-add SYS_ADMIN --security-opt no-new-privileges \
    -v "$(realpath "${work}/cases"):/cases:ro" -v "$(realpath "${work}/raw/${platform}"):/raw" \
    "$(image_of "${platform}")" bash -c "${inside}"
done
uv run --frozen python tools/molecule/sysctl_reader.py parse "${cases}" "${work}/raw" "${verdicts}"
