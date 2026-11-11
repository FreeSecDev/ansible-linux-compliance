#!/usr/bin/env bash
# The part of sysctl-reader-verdicts.sh that runs in each throwaway container (FREES-107). Docker
# starts it as root with CAP_SYS_ADMIN and CAP_SETFCAP only (CAP_SETFCAP lets root map itself in a
# new user namespace). It checks that /proc/sys is Docker's one read-only proc mount and then runs
# itself again in a new user and mount namespace, where Docker's read-only flags are locked and no
# remount can reach a kernel parameter of the host. There it mounts a private tmpfs over /proc/sys,
# checks it, and lets the real readers write every case into it. Each reader runs under `timeout`
# and a limit of its address space, because a reader may block on a FIFO or read a device such as
# /dev/zero without end; `/raw/<case>.<reader>.status` says whether it ended (`done`) or was
# stopped (`timeout`). For a case that names keys to trace (`/cases/<case>/trace.list`) the reader
# starts stopped and /cases/sysctl_trace.py attaches to it and records every write to those keys
# in order in `/raw/<case>.<reader>.writes`; a failure of the tracing stops the generator.
set -eu

if [ "${1:-}" != inner ]; then
  mounts="$(cut -d" " -f5 /proc/self/mountinfo | grep -c -x /proc/sys || true)"
  if [ "${mounts}" != 1 ]; then
    echo "error: ${mounts} mounts at /proc/sys instead of Docker's one; nothing ran" >&2
    exit 3
  fi
  options="$(cut -d" " -f5,6 /proc/self/mountinfo | grep "^/proc/sys " | cut -d" " -f2)"
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

# Seconds that a reader may run, and its address space in KiB.
limit=10
memory=1048576

# run_reader <case> <reader> <command ...>: reset the tree, run one reader and record the tree.
run_reader() {
  local name="$1" program="$2" status=0 reader
  shift 2
  reset_tree
  if [ -s "/cases/${name}/trace.list" ]; then
    # The reader stops itself before it starts, so that the tracer sees every system call of it.
    (ulimit -v "${memory}"; kill -STOP "${BASHPID}"; exec "$@") > /dev/null 2>&1 &
    reader=$!
    timeout -k 2 "${limit}" python3 /cases/sysctl_trace.py "${reader}" "/cases/${name}/trace.list" \
      "/raw/${name}.${program}.writes" || status=$?
    kill -KILL "${reader}" 2> /dev/null || true
    wait "${reader}" || true
    case "${status}" in
      0 | 124 | 137) ;;
      *) echo "error: tracing ${program} for ${name} failed with status ${status}" >&2; exit 3 ;;
    esac
  else
    (ulimit -v "${memory}"; exec timeout -k 2 "${limit}" "$@") > /dev/null 2>&1 || status=$?
  fi
  case "${status}" in
    124 | 137) echo "timeout" ;;
    *) echo "done" ;;
  esac > "/raw/${name}.${program}.status"
  record_tree > "/raw/${name}.${program}.values"
}

directories=(/etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /srv /etc/ufw)
for case in /cases/*/; do
  name="$(basename "${case}")"
  mkdir -p "${directories[@]}"
  find "${directories[@]}" -mindepth 1 -delete
  rm -f /etc/sysctl.conf /etc/default/ufw
  cp -RP --preserve=mode,links "${case}root/." /
  if [ -x /usr/lib/systemd/systemd-sysctl ]; then
    run_reader "${name}" systemd /usr/lib/systemd/systemd-sysctl
  fi
  run_reader "${name}" procps sysctl --system
done
