#!/usr/bin/env bash
set -euo pipefail

usage='usage: galaxy-collections.sh fetch <pins file> <directory>, install <pins file> <directory> <collections path>, or lock <requirements file>'
mode="${1:?${usage}}"
galaxy="https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections"
name_pattern='^[a-z0-9][a-z0-9_]*\.[a-z0-9][a-z0-9_]*$'
version_pattern='^[0-9]+\.[0-9]+\.[0-9]+$'
max_size=67108864

declare -a names=() versions=() digests=() sizes=()

read_pins() {
  local pins="$1" kind name version digest size extra
  if [[ ! -f "${pins}" || -L "${pins}" ]]; then
    printf 'error: %s is not a regular file\n' "${pins}" >&2
    exit 2
  fi
  while read -r kind name version digest size extra || [[ -n "${kind:-}" ]]; do
    [[ -z "${kind}" ]] && continue
    if [[ "${kind}" != collection || -n "${extra}" ]]; then
      printf 'error: every line of %s must be: collection <name> <version> <sha256> <size>\n' "${pins}" >&2
      exit 2
    fi
    if [[ ! "${name}" =~ ${name_pattern} || ! "${version}" =~ ${version_pattern} ]]; then
      printf 'error: %s %s is not a collection name and exact version\n' "${name}" "${version}" >&2
      exit 2
    fi
    if [[ ! "${digest}" =~ ^[0-9a-f]{64}$ ]]; then
      printf 'error: the SHA-256 of %s is not 64 lower-case hex digits\n' "${name}" >&2
      exit 2
    fi
    if [[ ! "${size}" =~ ^[0-9]+$ || "${size}" -gt "${max_size}" ]]; then
      printf 'error: the size of %s is not a bound\n' "${name}" >&2
      exit 2
    fi
    names+=("${name}")
    versions+=("${version}")
    digests+=("${digest}")
    sizes+=("${size}")
  done < "${pins}"
  if [[ ${#names[@]} -eq 0 ]]; then
    printf 'error: %s pins no collection\n' "${pins}" >&2
    exit 2
  fi
}

artifact() {
  printf '%s-%s.tar.gz' "${names[$1]//./-}" "${versions[$1]}"
}

is_verified() {
  [[ -f "$1" && ! -L "$1" ]] \
    && [[ "$(stat -c %s "$1")" == "${sizes[$2]}" ]] \
    && printf '%s  %s\n' "${digests[$2]}" "$1" | sha256sum --check --strict --quiet
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

download() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 4 --retry-delay 10 --retry-all-errors --connect-timeout 20 --max-time 90 "$@"
}

fetch_all() {
  local directory="$1" index name
  mkdir -p "${directory}"
  for index in "${!names[@]}"; do
    name="$(artifact "${index}")"
    if is_verified "${directory}/${name}" "${index}"; then
      printf 'reusing the verified %s\n' "${name}"
      continue
    fi
    rm -f "${directory}/${name}"
    download --max-filesize "${sizes[${index}]}" --output "${work_dir}/${name}" "${galaxy}/artifacts/${name}"
    if ! is_verified "${work_dir}/${name}" "${index}"; then
      printf 'error: %s/artifacts/%s does not match the pinned SHA-256 and size\n' "${galaxy}" "${name}" >&2
      exit 1
    fi
    mv "${work_dir}/${name}" "${directory}/${name}"
    printf 'downloaded and verified %s\n' "${name}"
  done
  find "${directory}" -mindepth 1 -maxdepth 1 -name '*.tar.gz' -print0 | while IFS= read -r -d '' stale; do
    for index in "${!names[@]}"; do
      [[ "$(basename "${stale}")" == "$(artifact "${index}")" ]] && continue 2
    done
    rm -f -- "${stale}"
    printf 'removed the unpinned %s\n' "$(basename "${stale}")"
  done
  printf 'every pinned collection is verified in %s\n' "${directory}"
}

install_all() {
  local directory="$1" collections_path="$2" index name
  local -a files=()
  mkdir -m 0700 "${work_dir}/artifacts"
  for index in "${!names[@]}"; do
    name="$(artifact "${index}")"
    if ! is_verified "${directory}/${name}" "${index}"; then
      printf 'error: %s/%s is missing or does not match its pin; nothing was installed\n' "${directory}" "${name}" >&2
      printf 'error: run make molecule-collections-fetch, which is the only step that contacts Galaxy\n' >&2
      exit 1
    fi
    cp -- "${directory}/${name}" "${work_dir}/artifacts/${name}"
    if ! is_verified "${work_dir}/artifacts/${name}" "${index}"; then
      printf 'error: the copy of %s does not match its pin; nothing was installed\n' "${name}" >&2
      exit 1
    fi
    files+=("${work_dir}/artifacts/${name}")
  done
  ANSIBLE_GALAXY_SERVER=https://galaxy.invalid ANSIBLE_GALAXY_SERVER_LIST='' \
    ansible-galaxy collection install --offline --force -p "${collections_path}" -- "${files[@]}"
  printf 'installed %d verified collections offline; Galaxy was not contacted\n' "${#files[@]}"
}

lock_all() {
  local requirements="$1" name version metadata digest size filename dependency
  local -a required=()
  if [[ ! -f "${requirements}" || -L "${requirements}" ]]; then
    printf 'error: %s is not a regular file\n' "${requirements}" >&2
    exit 2
  fi
  if ! awk '
    /^---$/ || /^collections:$/ || /^$/ { next }
    /^  - name: / && NF == 3 && name == "" { name = $3; next }
    /^    version: / && NF == 2 && name != "" { version = $2; gsub(/"/, "", version); print name, version; name = ""; next }
    { failed = NR; exit }
    END { if (failed || name != "") exit 2 }' "${requirements}" > "${work_dir}/required"; then
    printf 'error: %s must list "- name:" and "version:" pairs under collections only\n' "${requirements}" >&2
    exit 2
  fi
  while read -r name version; do
    required+=("${name} ${version}")
  done < "${work_dir}/required"
  if [[ ${#required[@]} -eq 0 ]]; then
    printf 'error: %s requires no collection\n' "${requirements}" >&2
    exit 2
  fi
  for entry in "${required[@]}"; do
    name="${entry% *}"
    version="${entry#* }"
    if [[ ! "${name}" =~ ${name_pattern} || ! "${version}" =~ ${version_pattern} ]]; then
      printf 'error: %s %s is not a collection name and exact version\n' "${name}" "${version}" >&2
      exit 2
    fi
    metadata="${work_dir}/${name}.json"
    download --max-filesize 1048576 --output "${metadata}" \
      "${galaxy}/index/${name%%.*}/${name#*.}/versions/${version}/"
    digest="$(jq -er '.artifact.sha256' "${metadata}")"
    size="$(jq -er '.artifact.size' "${metadata}")"
    filename="$(jq -er '.artifact.filename' "${metadata}")"
    if [[ "${filename}" != "${name//./-}-${version}.tar.gz" ]]; then
      printf 'error: Galaxy names the artifact of %s %s %s\n' "${name}" "${version}" "${filename}" >&2
      exit 1
    fi
    while IFS= read -r dependency; do
      if ! printf '%s\n' "${required[@]}" | grep -q -- "^${dependency//./\\.} "; then
        printf 'error: %s needs %s; pin it in %s\n' "${name}" "${dependency}" "${requirements}" >&2
        exit 1
      fi
    done < <(jq -r '.metadata.dependencies // {} | keys[]' "${metadata}")
    printf 'collection %s %s %s %s\n' "${name}" "${version}" "${digest}" "${size}"
  done
}

case "${mode}" in
  fetch)
    read_pins "${2:?${usage}}"
    fetch_all "${3:?${usage}}"
    ;;
  install)
    read_pins "${2:?${usage}}"
    install_all "${3:?${usage}}" "${4:?${usage}}"
    ;;
  lock) lock_all "${2:?${usage}}" ;;
  *)
    printf 'error: unknown mode %s; %s\n' "${mode}" "${usage}" >&2
    exit 2
    ;;
esac
