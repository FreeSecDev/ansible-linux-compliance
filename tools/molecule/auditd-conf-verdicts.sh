#!/usr/bin/env bash
# Runs the auditd of each Molecule image on every auditd.conf case and records the verdict table
# (FREES-110, tools/molecule/auditd_conf_verdicts.py). Only the verified instance images of the
# plan are used, each case in a new container without network and without capabilities, which
# is removed afterwards. Nothing runs on the workstation itself.
set -euo pipefail

usage='usage: auditd-conf-verdicts.sh <image plan> <table>'
plan="${1:?${usage}}"
table="${2:?${usage}}"
label=org.freesecdev.molecule.inputs
case_timeout="${AUDITD_CONF_CASE_TIMEOUT:-60}"
python=(uv run --frozen python -m tools.molecule.auditd_conf_verdicts)

if [[ ! "${case_timeout}" =~ ^[0-9]{1,3}$ ]]; then
  printf 'error: AUDITD_CONF_CASE_TIMEOUT must be a small whole number\n' >&2
  exit 2
fi
if [[ ! -f "${plan}" || -L "${plan}" ]]; then
  printf 'error: %s is not a regular file\n' "${plan}" >&2
  exit 2
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

in_image() {
  docker run --rm --network none --cap-drop ALL --entrypoint "$2" "$1" "${@:3}"
}

run_case() {
  local image="$1" conf="$2" out="$3" status_file="$4" id status
  id="$(docker create --network none --cap-drop ALL --entrypoint /sbin/auditd "${image}" -f -n -c /etc/audit)"
  tar --owner=0 --group=0 --mode=0640 --transform 's|.*|auditd.conf|' -C "$(dirname "${conf}")" \
    -cf - "$(basename "${conf}")" | docker cp - "${id}:/etc/audit"
  status=0
  timeout "${case_timeout}" docker start -a "${id}" > "${out}" 2>&1 || status=$?
  docker rm -f "${id}" > /dev/null
  printf '%s\n' "${status}" > "${status_file}"
}

while read -r key tag _ _ || [[ -n "${key:-}" ]]; do
  [[ -z "${key}" ]] && continue
  if [[ ! "${key}" =~ ^[a-z][a-z0-9_]{0,30}$ || ! "${tag}" =~ ^[0-9a-f]{12}-[0-9a-f]{12}$ ]]; then
    printf 'error: %s %s is not an image key and tag of the plan\n' "${key}" "${tag}" >&2
    exit 2
  fi
  image="freesecdev-molecule/${key}:${tag}"
  found="$(docker image inspect --format "{{index .Config.Labels \"${label}\"}}" "${image}" 2>/dev/null || true)"
  if [[ "${found}" != "${tag}" ]]; then
    printf 'error: %s is not a verified Molecule image; run make molecule-images first\n' "${image}" >&2
    exit 2
  fi
  case "${key}" in
    ubuntu)
      package=auditd
      # shellcheck disable=SC2016  # ${Version} is the dpkg-query field, not a shell expansion
      version="$(in_image "${image}" /usr/bin/dpkg-query -W -f '${Version}' auditd)" ;;
    rhel_compatible)
      package=audit
      version="$(in_image "${image}" /usr/bin/rpm -q --qf '%{VERSION}-%{RELEASE}' audit)" ;;
    *)
      printf 'error: no auditd package is known for the image %s\n' "${key}" >&2
      exit 2 ;;
  esac
  megabytes="$(in_image "${image}" /usr/bin/df -Pm /var/log/audit | awk 'NR == 2 { print $2 }')"
  if [[ ! "${megabytes}" =~ ^[0-9]{1,12}$ ]]; then
    printf 'error: the size of the log file system of %s cannot be read\n' "${image}" >&2
    exit 2
  fi
  base="${work_dir}/${key}.base"
  in_image "${image}" /usr/bin/cat /etc/audit/auditd.conf > "${base}"
  cases="${work_dir}/${key}.cases"
  results="${work_dir}/${key}.results"
  mkdir -p "${results}"
  "${python[@]}" cases --base "${base}" --output "${cases}"
  for conf in "${cases}"/*.conf; do
    name="$(basename "${conf}" .conf)"
    run_case "${image}" "${conf}" "${results}/${name}.out" "${results}/${name}.status"
  done
  "${python[@]}" table --platform "${key}" --base "${base}" --results "${results}" --package "${package}" \
    --version "${version}" --image "${image}" --log-megabytes "${megabytes}" --output "${table}"
done < "${plan}"
