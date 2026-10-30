#!/usr/bin/env bash
set -euo pipefail

pins="${1:?usage: fetch-cloud-images.sh <pins file> <cache directory> [platform ...]}"
cache_dir="${2:?usage: fetch-cloud-images.sh <pins file> <cache directory> [platform ...]}"
shift 2
pins_dir="$(cd "$(dirname "${pins}")" && pwd)"

if [[ ! -f "${pins}" || -L "${pins}" ]]; then
  printf 'error: %s is not a regular file\n' "${pins}" >&2
  exit 2
fi
for tool in curl gpg gpgv sha256sum; do
  if ! command -v "${tool}" >/dev/null; then
    printf 'error: %s is required to fetch and verify the cloud images\n' "${tool}" >&2
    exit 2
  fi
done

declare -A wanted=()
for platform in "$@"; do
  wanted["${platform}"]=1
done

selected() {
  [[ ${#wanted[@]} -eq 0 || -n "${wanted[$1]:-}" ]]
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

fetch() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-filesize "$3" --retry 3 --retry-all-errors --connect-timeout 30 --max-time 1800 \
    --output "$2" "$1"
}

is_verified() {
  [[ -f "$1" && ! -L "$1" ]] && printf '%s  %s\n' "$2" "$1" | sha256sum --check --strict --quiet
}

check_digest() {
  if [[ ! "$1" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'error: %s is not 64 lower-case hex digits\n' "$1" >&2
    exit 2
  fi
}

check_url() {
  if [[ ! "$1" =~ ^https://(cloud-images\.ubuntu\.com|archive\.ubuntu\.com|dl\.rockylinux\.org)/[A-Za-z0-9._+/~-]+$ ]]; then
    printf 'error: %s is not an HTTPS URL of a pinned vendor host\n' "$1" >&2
    exit 2
  fi
}

check_name() {
  if [[ ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]*$ ]]; then
    printf 'error: %s is not a plain file name\n' "$1" >&2
    exit 2
  fi
}

store() {
  local url="$1" digest="$2" size="$3" target="$4" name
  name="$(basename "${target}")"
  if is_verified "${target}" "${digest}"; then
    printf 'reusing the verified %s\n' "${name}"
    return
  fi
  rm -f "${target}"
  fetch "${url}" "${work_dir}/${name}" "${size}"
  if ! is_verified "${work_dir}/${name}" "${digest}"; then
    printf 'error: %s does not match the pinned SHA-256 %s\n' "${url}" "${digest}" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${target}")"
  mv "${work_dir}/${name}" "${target}"
  printf 'downloaded and verified %s\n' "${url}"
}

verify_listing() {
  local platform="$1" checksums_url="$2" signature_url="$3" key="$4" fingerprint="$5" file="$6" digest="$7"
  local key_path="${pins_dir}/${key}" listed fingerprints
  if [[ ! "${key}" =~ ^keys/[a-z0-9][a-z0-9.-]*\.asc$ ]]; then
    printf 'error: the signing key of %s must be a file below keys/ next to the pins\n' "${platform}" >&2
    exit 2
  fi
  check_url "${checksums_url}"
  check_url "${signature_url}"
  if [[ ! "${fingerprint}" =~ ^[0-9A-F]{40}$ ]]; then
    printf 'error: the key fingerprint of %s is not 40 upper-case hex digits\n' "${platform}" >&2
    exit 2
  fi
  if [[ ! -f "${key_path}" || -L "${key_path}" ]]; then
    printf 'error: the signing key %s of %s is missing\n' "${key}" "${platform}" >&2
    exit 2
  fi
  fingerprints="$(gpg --batch --no-options --homedir "${work_dir}/gnupg" --with-colons --show-keys "${key_path}" 2>/dev/null \
    | awk -F: '$1 == "pub" { primary = 1; next } $1 == "fpr" && primary { print $10; primary = 0 }')"
  if [[ "${fingerprints}" != "${fingerprint}" ]]; then
    printf 'error: %s must hold exactly the key %s, found %s\n' "${key}" "${fingerprint}" "${fingerprints:-none}" >&2
    exit 1
  fi
  gpg --batch --no-options --homedir "${work_dir}/gnupg" --dearmor < "${key_path}" > "${work_dir}/${platform}.gpg"
  fetch "${checksums_url}" "${work_dir}/${platform}.checksums" 1048576
  fetch "${signature_url}" "${work_dir}/${platform}.signature" 65536
  if ! gpgv --keyring "${work_dir}/${platform}.gpg" "${work_dir}/${platform}.signature" \
    "${work_dir}/${platform}.checksums" 2>"${work_dir}/${platform}.gpgv"; then
    cat "${work_dir}/${platform}.gpgv" >&2
    printf 'error: the signature of %s does not verify with %s\n' "${checksums_url}" "${fingerprint}" >&2
    exit 1
  fi
  listed="$(tr -d '\r' < "${work_dir}/${platform}.checksums" | awk -v file="${file}" '
    $2 == "*" file || $2 == file { print $1 }
    $1 == "SHA256" && $2 == "(" file ")" && $3 == "=" { print $4 }
  ')"
  if [[ "${listed}" != "${digest}" ]]; then
    printf 'error: the signed checksum file %s lists %s for %s, not the pinned %s\n' \
      "${checksums_url}" "${listed:-nothing}" "${file}" "${digest}" >&2
    exit 1
  fi
  printf 'the signed checksum file of %s lists the pinned SHA-256 of %s\n' "${platform}" "${file}"
}

mkdir -p "${work_dir}/gnupg" "${cache_dir}"
chmod 0700 "${work_dir}/gnupg"
declare -A image_file=() image_digest=() image_listed=()
found=0
while read -r kind platform first second third fourth fifth; do
  [[ -z "${kind}" ]] && continue
  if [[ ! "${platform}" =~ ^[a-z][a-z0-9_]{0,30}$ ]]; then
    printf 'error: %s names an invalid platform %s\n' "${pins}" "${platform}" >&2
    exit 2
  fi
  selected "${platform}" || continue
  case "${kind}" in
    image)
      check_name "${first}"
      check_url "${second}"
      check_digest "${third}"
      if [[ ! "${fourth}" =~ ^[0-9]+$ || "${fourth}" -gt 2147483648 ]]; then
        printf 'error: the size of the %s image is not a bound\n' "${platform}" >&2
        exit 2
      fi
      if [[ "$(basename "${second}")" != "${first}" ]]; then
        printf 'error: the %s image URL does not end in %s\n' "${platform}" "${first}" >&2
        exit 2
      fi
      image_file["${platform}"]="${first}"
      image_digest["${platform}"]="${third}"
      store "${second}" "${third}" "${fourth}" "${cache_dir}/images/${third}.qcow2"
      found=$((found + 1))
      ;;
    listing)
      if [[ -z "${image_file[${platform}]:-}" ]]; then
        printf 'error: the listing of %s must follow its image line\n' "${platform}" >&2
        exit 2
      fi
      verify_listing "${platform}" "${first}" "${second}" "${third}" "${fourth}" \
        "${image_file[${platform}]}" "${image_digest[${platform}]}"
      image_listed["${platform}"]=1
      ;;
    package)
      check_url "${first}"
      check_digest "${second}"
      check_name "$(basename "${first}")"
      if [[ ! "${third}" =~ ^[0-9]+$ || "${third}" -gt 268435456 ]]; then
        printf 'error: the size of %s is not a bound\n' "${first}" >&2
        exit 2
      fi
      store "${first}" "${second}" "${third}" "${cache_dir}/packages/${platform}/$(basename "${first}")"
      ;;
    *)
      printf 'error: %s has the unknown line kind %s\n' "${pins}" "${kind}" >&2
      exit 2
      ;;
  esac
  if [[ -n "${fifth}" ]]; then
    printf 'error: a line of %s has too many fields\n' "${pins}" >&2
    exit 2
  fi
done < "${pins}"

for platform in "${!image_file[@]}"; do
  if [[ -z "${image_listed[${platform}]:-}" ]]; then
    printf 'error: the %s image has no signed checksum listing in %s\n' "${platform}" "${pins}" >&2
    exit 1
  fi
done
if [[ "${found}" -eq 0 ]]; then
  printf 'error: no image of the requested platforms is pinned in %s\n' "${pins}" >&2
  exit 2
fi
printf 'every requested cloud image and package is verified in %s\n' "${cache_dir}"
