#!/usr/bin/env bash
# The part of sysctl-reader-verdicts.sh that runs in each throwaway container (FREES-107). Docker
# starts it as root with CAP_SYS_ADMIN and CAP_SETFCAP only (CAP_SETFCAP lets root map itself in a
# new user namespace). It checks that /proc/sys is Docker's read-only proc mount and then runs
# itself again in a new user and mount namespace, where Docker's read-only flags are locked and no
# remount can reach a kernel parameter of the host. There it mounts a private tmpfs over /proc/sys,
# checks it, and lets the real readers write every case into it.
set -eu

if [ "${1:-}" != inner ]; then
  options="$(grep " /proc/sys " /proc/self/mountinfo | head -n 1 | cut -d" " -f6)"
  case ",${options}," in
    *,ro,*) ;;
    *) echo "error: /proc/sys is not read-only before the tmpfs is mounted; nothing ran" >&2; exit 3 ;;
  esac
  exec unshare --user --map-root-user --mount --propagation private bash "$0" inner
fi

if [ "$(tr -s " " < /proc/self/uid_map)" != " 0 0 1" ]; then
  echo "error: the readers would not run in a user namespace of their own; nothing ran" >&2
  exit 3
fi
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

directories=(/etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /srv /etc/ufw)
for case in /cases/*/; do
  name="$(basename "${case}")"
  mkdir -p "${directories[@]}"
  find "${directories[@]}" -mindepth 1 -delete
  rm -f /etc/sysctl.conf /etc/default/ufw
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
