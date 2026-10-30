#!/usr/bin/env bash
set -euo pipefail

usage='usage: libvirt-host-packages.sh fetch|install <pins file> <directory>, or resolve <pins file>'
mode="${1:?${usage}}"
pins="${2:?${usage}}"
case "${mode}" in
  fetch | install) directory="${3:?${usage}}" ;;
  resolve) directory="" ;;
  *)
    printf 'error: unknown mode %s; %s\n' "${mode}" "${usage}" >&2
    exit 2
    ;;
esac

if [[ ! -f "${pins}" || -L "${pins}" ]]; then
  printf 'error: %s is not a regular file\n' "${pins}" >&2
  exit 2
fi

snapshot=""
declare -a require_names=() require_versions=()
declare -a deb_names=() deb_versions=() deb_paths=() deb_digests=() deb_sizes=()

while read -r kind first second third fourth fifth sixth; do
  [[ -z "${kind}" ]] && continue
  if [[ -n "${sixth}" ]]; then
    printf 'error: a line of %s has too many fields\n' "${pins}" >&2
    exit 2
  fi
  case "${kind}" in
    snapshot)
      if [[ -n "${snapshot}" || ! "${first}" =~ ^[0-9]{8}T[0-9]{6}Z$ || -n "${second}" ]]; then
        printf 'error: %s must name one snapshot as YYYYMMDDTHHMMSSZ\n' "${pins}" >&2
        exit 2
      fi
      snapshot="${first}"
      ;;
    require | deb)
      if [[ ! "${first}" =~ ^[a-z0-9][a-z0-9.+-]+$ ]]; then
        printf 'error: %s is not a package name\n' "${first}" >&2
        exit 2
      fi
      if [[ ! "${second}" =~ ^[A-Za-z0-9.+~:-]+$ ]]; then
        printf 'error: %s is not a package version\n' "${second}" >&2
        exit 2
      fi
      if [[ "${kind}" == require ]]; then
        if [[ -n "${third}" ]]; then
          printf 'error: a require line of %s has too many fields\n' "${pins}" >&2
          exit 2
        fi
        require_names+=("${first}")
        require_versions+=("${second}")
        continue
      fi
      if [[ ! "${third}" =~ ^pool/(main|universe)/[a-z0-9]+/[a-z0-9][a-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+~_-]*\.deb$ ]] \
        || [[ "$(basename "${third}")" != "${first}_"* ]]; then
        printf 'error: %s is not a pool path of %s in the Ubuntu archive\n' "${third}" "${first}" >&2
        exit 2
      fi
      if [[ ! "${fourth}" =~ ^[0-9a-f]{64}$ ]]; then
        printf 'error: the SHA-256 of %s is not 64 lower-case hex digits\n' "${first}" >&2
        exit 2
      fi
      if [[ ! "${fifth}" =~ ^[0-9]+$ || "${fifth}" -gt 268435456 ]]; then
        printf 'error: the size of %s is not a bound\n' "${first}" >&2
        exit 2
      fi
      deb_names+=("${first}")
      deb_versions+=("${second}")
      deb_paths+=("${third}")
      deb_digests+=("${fourth}")
      deb_sizes+=("${fifth}")
      ;;
    *)
      printf 'error: %s has the unknown line kind %s\n' "${pins}" "${kind}" >&2
      exit 2
      ;;
  esac
done < "${pins}"

if [[ -z "${snapshot}" || ${#require_names[@]} -eq 0 ]]; then
  printf 'error: %s must name a snapshot and at least one required package\n' "${pins}" >&2
  exit 2
fi
archive="https://snapshot.ubuntu.com/ubuntu/${snapshot}"

is_verified() {
  [[ -f "$1" && ! -L "$1" ]] \
    && [[ "$(stat -c %s "$1")" == "$3" ]] \
    && printf '%s  %s\n' "$2" "$1" | sha256sum --check --strict --quiet
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

fetch_all() {
  local index name target
  mkdir -p "${directory}"
  for index in "${!deb_names[@]}"; do
    name="$(basename "${deb_paths[${index}]}")"
    target="${directory}/${name}"
    if is_verified "${target}" "${deb_digests[${index}]}" "${deb_sizes[${index}]}"; then
      printf 'reusing the verified %s\n' "${name}"
      continue
    fi
    rm -f "${target}"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --max-filesize "${deb_sizes[${index}]}" --retry 5 --retry-delay 30 --retry-all-errors \
      --connect-timeout 30 --max-time 900 --output "${work_dir}/${name}" "${archive}/${deb_paths[${index}]}"
    if ! is_verified "${work_dir}/${name}" "${deb_digests[${index}]}" "${deb_sizes[${index}]}"; then
      printf 'error: %s/%s does not match the pinned SHA-256 and size\n' "${archive}" "${deb_paths[${index}]}" >&2
      exit 1
    fi
    mv "${work_dir}/${name}" "${target}"
    printf 'downloaded and verified %s\n' "${name}"
  done
  printf 'every pinned host package is verified in %s\n' "${directory}"
}

install_all() {
  local index name target installed
  local -a files=()
  if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
    printf 'error: install changes the system packages and runs only on a GitHub-hosted runner\n' >&2
    exit 2
  fi
  for index in "${!deb_names[@]}"; do
    target="${directory}/$(basename "${deb_paths[${index}]}")"
    if ! is_verified "${target}" "${deb_digests[${index}]}" "${deb_sizes[${index}]}"; then
      printf 'error: %s is missing or does not match its pin; nothing was installed\n' "${target}" >&2
      exit 1
    fi
  done
  for index in "${!deb_names[@]}"; do
    name="${deb_names[${index}]}"
    installed="$(dpkg-query -W -f='${db:Status-Abbrev}${Version}' "${name}" 2>/dev/null || true)"
    if [[ "${installed}" == "ii "* ]] && dpkg --compare-versions "${installed#ii }" ge "${deb_versions[${index}]}"; then
      printf 'keeping the installed %s %s\n' "${name}" "${installed#ii }"
      continue
    fi
    files+=("$(realpath "${directory}/$(basename "${deb_paths[${index}]}")")")
  done
  mkdir -p "${work_dir}/lists/partial" "${work_dir}/sources.list.d"
  if [[ ${#files[@]} -gt 0 ]]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::SourceList=/dev/null \
      -o "Dir::Etc::SourceParts=${work_dir}/sources.list.d" -o "Dir::State::Lists=${work_dir}/lists" \
      -o Dpkg::Use-Pty=0 install -y --no-install-recommends -- "${files[@]}"
  fi
  for index in "${!require_names[@]}"; do
    installed="$(dpkg-query -W -f='${Version}' "${require_names[${index}]}" 2>/dev/null || true)"
    if [[ "${installed}" != "${require_versions[${index}]}" ]]; then
      printf 'error: %s is %s, not the pinned %s\n' "${require_names[${index}]}" "${installed:-missing}" \
        "${require_versions[${index}]}" >&2
      exit 1
    fi
  done
  printf 'installed the required host packages from %d verified files\n' "${#files[@]}"
}

resolve_all() {
  local index file name version
  local -a options specs=()
  mkdir -p "${work_dir}/lists/partial" "${work_dir}/cache/archives/partial" "${work_dir}/parts" "${work_dir}/preferences"
  for suite in noble noble-updates noble-security; do
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s main universe\n' "${archive}" "${suite}"
  done > "${work_dir}/sources.list"
  options=(-o "Dir::Etc::SourceList=${work_dir}/sources.list" -o "Dir::Etc::SourceParts=${work_dir}/parts"
    -o "Dir::Etc::PreferencesParts=${work_dir}/preferences" -o "Dir::State::Lists=${work_dir}/lists"
    -o "Dir::Cache=${work_dir}/cache" -o "Dir::State::extended_states=${work_dir}/extended_states"
    -o Debug::NoLocking=1 -o APT::Architectures::=amd64 -o Acquire::Languages=none -o Acquire::Retries=5)
  apt-get "${options[@]}" -qq update >&2
  for index in "${!require_names[@]}"; do
    specs+=("${require_names[${index}]}=${require_versions[${index}]}")
  done
  printf 'snapshot %s\n' "${snapshot}"
  for index in "${!require_names[@]}"; do
    printf 'require %s %s\n' "${require_names[${index}]}" "${require_versions[${index}]}"
  done
  apt-get "${options[@]}" -qq install --print-uris --no-install-recommends "${specs[@]}" > "${work_dir}/uris"
  while read -r _ file _; do
    name="${file%%_*}"
    version="${file#*_}"
    version="${version%_*}"
    version="${version//%3a/:}"
    apt-cache "${options[@]}" show "${name}=${version}" | awk '
      /^Package: / { package = $2 } /^Version: / { version = $2 } /^Filename: / { path = $2 }
      /^Size: / { size = $2 } /^SHA256: / { digest = $2 }
      /^$/ { if (package != "") { exit } }
      END { if (package != "") print "deb", package, version, path, digest, size }'
  done < "${work_dir}/uris"
  printf 'resolved against the packages of this host; run it on the runner image that installs them\n' >&2
}

case "${mode}" in
  fetch) fetch_all ;;
  install) install_all ;;
  resolve) resolve_all ;;
esac
