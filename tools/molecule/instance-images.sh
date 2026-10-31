#!/usr/bin/env bash
set -euo pipefail

usage='usage: instance-images.sh build <plan> <directory> <record> [save], load <plan> <directory> <record> <image ids>, or ids <record>'
mode="${1:?${usage}}"
label=org.freesecdev.molecule.inputs
attempts="${MOLECULE_IMAGE_BUILD_ATTEMPTS:-3}"
attempt_timeout="${MOLECULE_IMAGE_BUILD_TIMEOUT:-200}"
pull_timeout="${MOLECULE_IMAGE_PULL_TIMEOUT:-120}"
retry_delay="${MOLECULE_IMAGE_RETRY_DELAY:-15}"
transfer_timeout="${MOLECULE_IMAGE_TRANSFER_TIMEOUT:-600}"
id_pattern='^sha256:[0-9a-f]{64}$'

declare -a keys=() tags=() bases=() dockerfiles=()

for setting in "${attempts}" "${attempt_timeout}" "${pull_timeout}" "${retry_delay}" "${transfer_timeout}"; do
  if [[ ! "${setting}" =~ ^[0-9]{1,5}$ ]]; then
    printf 'error: the attempts, timeouts and delay must be small whole numbers\n' >&2
    exit 2
  fi
done

read_plan() {
  local plan="$1" key tag base dockerfile
  if [[ ! -f "${plan}" || -L "${plan}" ]]; then
    printf 'error: %s is not a regular file\n' "${plan}" >&2
    exit 2
  fi
  while read -r key tag base dockerfile || [[ -n "${key:-}" ]]; do
    [[ -z "${key}" ]] && continue
    if [[ ! "${key}" =~ ^[a-z][a-z0-9_]{0,30}$ || ! "${tag}" =~ ^[0-9a-f]{12}-[0-9a-f]{12}$ ]]; then
      printf 'error: %s %s is not an image key and tag of the plan\n' "${key}" "${tag}" >&2
      exit 2
    fi
    if [[ ! "${base}" =~ ^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$ ]]; then
      printf 'error: the base of %s is not pinned by digest\n' "${key}" >&2
      exit 2
    fi
    if [[ ! "${dockerfile}" =~ /extensions/molecule/shared/images/[a-z0-9-]+\.Dockerfile$ \
      || ! -f "${dockerfile}" || -L "${dockerfile}" ]]; then
      printf 'error: the Dockerfile of %s is not one of extensions/molecule/shared/images\n' "${key}" >&2
      exit 2
    fi
    keys+=("${key}")
    tags+=("${tag}")
    bases+=("${base}")
    dockerfiles+=("${dockerfile}")
  done < "${plan}"
  if [[ ${#keys[@]} -eq 0 ]]; then
    printf 'error: %s plans no image\n' "${plan}" >&2
    exit 2
  fi
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

target() {
  printf 'freesecdev-molecule/%s:%s' "${keys[$1]}" "${tags[$1]}"
}

image_id() {
  docker image inspect --format '{{.Id}}' "$1"
}

layers() {
  docker image inspect --format '{{range .RootFS.Layers}}{{println .}}{{end}}' "$1" | sed '/^$/d'
}

# The image carries the inputs label of its tag, and its layers start with exactly the layers of
# the pinned base image, which was pulled by digest.
is_verified() {
  local index="$1" base_layers="$2" found count
  found="$(docker image inspect --format "{{index .Config.Labels \"${label}\"}}" "$(target "${index}")" 2>/dev/null)" \
    || return 1
  [[ "${found}" == "${tags[${index}]}" ]] || return 1
  count="$(wc -l < "${base_layers}")"
  [[ "${count}" -gt 0 ]] || return 1
  layers "$(target "${index}")" > "${base_layers}.image" || return 1
  [[ "$(wc -l < "${base_layers}.image")" -gt "${count}" ]] || return 1
  head -n "${count}" "${base_layers}.image" | cmp -s - "${base_layers}"
}

retry() {
  local what="$1" limit="$2" attempt
  shift 2
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if timeout --kill-after=30 "${limit}" "$@"; then
      return 0
    fi
    printf 'warning: %s failed or exceeded %s seconds (attempt %d of %d)\n' "${what}" "${limit}" "${attempt}" \
      "${attempts}" >&2
    if ((attempt < attempts)); then
      sleep "${retry_delay}"
    fi
  done
  printf 'error: %s failed %d times\n' "${what}" "${attempts}" >&2
  return 1
}

load_archive() {
  local index="$1" archive="$2" output="${work_dir}/load-${keys[$1]}"
  zstd --decompress --stdout --quiet -- "${archive}" | timeout "${transfer_timeout}" docker load > "${output}" \
    || return 1
  cat "${output}"
  # The archive must hold the target and nothing else: any other loaded name or untagged image is refused.
  if grep -E '^Loaded image' "${output}" | grep -Evqx "Loaded image: (docker\.io/)?$(target "${index}")"; then
    printf 'error: the archive loads more than %s\n' "$(target "${index}")" >&2
    return 1
  fi
  grep -Eqx "Loaded image: (docker\.io/)?$(target "${index}")" "${output}"
}

prepare_one() {
  local index="$1" save="$2" key="${keys[$1]}" image cache base_layers reused=""
  image="$(target "${index}")"
  cache="${directory}/${key}"
  base_layers="${work_dir}/base-${key}"
  retry "pulling ${bases[${index}]}" "${pull_timeout}" docker pull --quiet "${bases[${index}]}"
  layers "${bases[${index}]}" > "${base_layers}"
  if [[ -f "${cache}/image.tar.zst" && ! -L "${cache}/image.tar.zst" ]]; then
    if load_archive "${index}" "${cache}/image.tar.zst" && is_verified "${index}" "${base_layers}"; then
      reused=cache
      printf 'reusing the cached %s, verified against its inputs label and the pinned base layers\n' "${image}"
    else
      printf 'warning: the cached %s does not verify; it is discarded and the image is built\n' "${image}" >&2
      docker image rm --force "${image}" > /dev/null 2>&1 || true
      rm -rf -- "${cache}"
    fi
  fi
  if [[ -z "${reused}" ]] && docker image inspect "${image}" > /dev/null 2>&1; then
    if is_verified "${index}" "${base_layers}"; then
      reused=daemon
      printf 'reusing the local %s, verified against its inputs label and the pinned base layers\n' "${image}"
    else
      docker image rm --force "${image}" > /dev/null
    fi
  fi
  if [[ -z "${reused}" ]]; then
    retry "building ${image}" "${attempt_timeout}" docker build --progress=plain --provenance=false \
      --file "${dockerfiles[${index}]}" --build-arg "BASE_IMAGE=${bases[${index}]}" \
      --label "${label}=${tags[${index}]}" --tag "${image}" "$(dirname "${dockerfiles[${index}]}")"
    if ! is_verified "${index}" "${base_layers}"; then
      printf 'error: the built %s does not carry its inputs label on the pinned base layers\n' "${image}" >&2
      exit 1
    fi
    printf 'built %s\n' "${image}"
  fi
  if [[ "${save}" == save ]]; then
    mkdir -p "${cache}"
    docker save "${image}" | zstd --quiet --threads=0 -3 --force -o "${cache}/image.tar.zst.partial"
    mv -- "${cache}/image.tar.zst.partial" "${cache}/image.tar.zst"
    printf 'saved %s to %s\n' "${image}" "${cache}/image.tar.zst"
  fi
  printf '%s %s %s\n' "${key}" "${tags[${index}]}" "$(image_id "${image}")" > "${work_dir}/result-${key}"
}

load_one() {
  local index="$1" key="${keys[$1]}" image expected found
  image="$(target "${index}")"
  expected="${expected_ids[${key}]:-}"
  if [[ -z "${expected}" ]]; then
    printf 'error: no image ID of %s was given; the molecule-images job records it\n' "${key}" >&2
    exit 1
  fi
  if [[ ! -f "${directory}/${key}/image.tar.zst" || -L "${directory}/${key}/image.tar.zst" ]]; then
    printf 'error: %s/%s/image.tar.zst is missing; this step loads the image of the molecule-images job and never builds one\n' \
      "${directory}" "${key}" >&2
    exit 1
  fi
  if ! load_archive "${index}" "${directory}/${key}/image.tar.zst"; then
    printf 'error: the archive in %s/%s does not hold %s\n' "${directory}" "${key}" "${image}" >&2
    exit 1
  fi
  found="$(image_id "${image}")"
  if [[ "${found}" != "${expected}" ]]; then
    docker image rm --force "${image}" > /dev/null 2>&1 || true
    printf 'error: %s has the image ID %s, not %s of the molecule-images job; nothing is built here\n' "${image}" \
      "${found}" "${expected}" >&2
    exit 1
  fi
  if [[ "$(docker image inspect --format "{{index .Config.Labels \"${label}\"}}" "${image}")" != "${tags[${index}]}" ]]; then
    printf 'error: %s does not carry the inputs label of its tag\n' "${image}" >&2
    exit 1
  fi
  printf 'loaded %s and verified its image ID %s; nothing was built\n' "${image}" "${found}"
  printf '%s %s %s\n' "${key}" "${tags[${index}]}" "${found}" > "${work_dir}/result-${key}"
}

write_record() {
  local record="$1" index key tag id
  {
    printf -- '---\n'
    for index in "${!keys[@]}"; do
      read -r key tag id < "${work_dir}/result-${keys[${index}]}"
      if [[ ! "${id}" =~ ${id_pattern} ]]; then
        printf 'error: %s has the malformed image ID %s\n' "${key}" "${id}" >&2
        exit 1
      fi
      printf '%s:\n  tag: "%s"\n  id: "%s"\n' "${key}" "${tag}" "${id}"
    done
  } > "${work_dir}/record"
  mkdir -p "$(dirname "${record}")"
  mv -- "${work_dir}/record" "${record}"
}

print_ids() {
  local record="$1" line key="" ids=""
  if [[ ! -f "${record}" || -L "${record}" ]]; then
    printf 'error: %s is not a regular file\n' "${record}" >&2
    exit 2
  fi
  while IFS= read -r line; do
    if [[ "${line}" == --- || "${line}" =~ ^\ \ tag:\ \"[0-9a-f]{12}-[0-9a-f]{12}\"$ ]]; then
      continue
    elif [[ "${line}" =~ ^([a-z][a-z0-9_]*):$ ]]; then
      key="${BASH_REMATCH[1]}"
    elif [[ -n "${key}" && "${line}" =~ ^\ \ id:\ \"(sha256:[0-9a-f]{64})\"$ ]]; then
      ids="${ids:+${ids} }${key}=${BASH_REMATCH[1]}"
      key=""
    else
      printf 'error: %s is not a record of verified images\n' "${record}" >&2
      exit 2
    fi
  done < "${record}"
  if [[ -z "${ids}" ]]; then
    printf 'error: %s records no image\n' "${record}" >&2
    exit 2
  fi
  printf '%s\n' "${ids}"
}

case "${mode}" in
  build)
    read_plan "${2:?${usage}}"
    directory="${3:?${usage}}"
    record="${4:?${usage}}"
    save="${5:-}"
    if [[ -n "${save}" && "${save}" != save ]]; then
      printf 'error: %s\n' "${usage}" >&2
      exit 2
    fi
    rm -f -- "${record}"
    declare -a pids=()
    for index in "${!keys[@]}"; do
      (
        set -o pipefail
        prepare_one "${index}" "${save}" 2>&1 | sed -u "s/^/[${keys[${index}]}] /"
      ) &
      pids+=("$!")
    done
    status=0
    for pid in "${pids[@]}"; do
      wait "${pid}" || status=1
    done
    if [[ "${status}" -ne 0 ]]; then
      printf 'error: an instance image could not be prepared\n' >&2
      exit 1
    fi
    write_record "${record}"
    ;;
  load)
    read_plan "${2:?${usage}}"
    directory="${3:?${usage}}"
    record="${4:?${usage}}"
    declare -A expected_ids=()
    for pair in ${5:-}; do
      if [[ ! "${pair}" =~ ^([a-z][a-z0-9_]*)=(sha256:[0-9a-f]{64})$ ]]; then
        printf 'error: %s is not <image>=<image ID>\n' "${pair}" >&2
        exit 2
      fi
      expected_ids["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    done
    rm -f -- "${record}"
    for index in "${!keys[@]}"; do
      load_one "${index}"
    done
    write_record "${record}"
    ;;
  ids) print_ids "${2:?${usage}}" ;;
  *)
    printf 'error: unknown mode %s; %s\n' "${mode}" "${usage}" >&2
    exit 2
    ;;
esac
