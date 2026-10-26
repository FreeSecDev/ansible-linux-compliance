#!/usr/bin/env bash
set -euo pipefail

download_dir="${1:?usage: fetch-scc.sh <download directory> <build context directory>}"
context_dir="${2:?usage: fetch-scc.sh <download directory> <build context directory>}"

for name in SCC_VERSION SCC_BUNDLE SCC_BUNDLE_URL SCC_BUNDLE_SIZE SCC_BUNDLE_SHA256 SCC_CHECKSUMS_URL \
  SCC_DEB_MEMBER SCC_DEB_SHA256 SCC_CSCC_SHA256; do
  if [[ -z "${!name:-}" ]]; then
    printf 'error: %s is not set; run this through make scc-fetch\n' "${name}" >&2
    exit 2
  fi
done
for digest in "${SCC_BUNDLE_SHA256}" "${SCC_DEB_SHA256}" "${SCC_CSCC_SHA256}"; do
  if [[ ! "${digest}" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'error: a pinned SHA-256 is not 64 lower-case hex digits\n' >&2
    exit 2
  fi
done
if [[ ! "${SCC_BUNDLE_URL}" =~ ^https://dl\.dod\.cyber\.mil/wp-content/uploads/stigs/zip/ ]] ||
  [[ ! "${SCC_CHECKSUMS_URL}" =~ ^https://dl\.dod\.cyber\.mil/wp-content/uploads/stigs/txt/ ]]; then
  printf 'error: SCC is fetched only from the official DISA download host\n' >&2
  exit 2
fi
if [[ "$(uname -s)" != 'Linux' || "$(uname -m)" != 'x86_64' ]]; then
  printf 'error: the pinned SCC bundle is the Linux x86_64 build\n' >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

fetch() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-filesize "$3" --retry 3 --retry-all-errors --output "$2" "$1"
}

bundle_is_verified() {
  [[ -f "$1" && ! -L "$1" ]] && printf '%s  %s\n' "${SCC_BUNDLE_SHA256}" "$1" | sha256sum --check --strict --quiet
}

bundle="${download_dir}/${SCC_BUNDLE}"
mkdir -p "${download_dir}"
if bundle_is_verified "${bundle}"; then
  printf 'reusing the verified SCC %s bundle in %s\n' "${SCC_VERSION}" "${download_dir}"
else
  rm -f "${bundle}"
  fetch "${SCC_BUNDLE_URL}" "${work_dir}/${SCC_BUNDLE}" "${SCC_BUNDLE_SIZE}"
  if [[ "$(stat -c %s "${work_dir}/${SCC_BUNDLE}")" != "${SCC_BUNDLE_SIZE}" ]]; then
    printf 'error: the SCC bundle does not have the pinned size %s\n' "${SCC_BUNDLE_SIZE}" >&2
    exit 1
  fi
  if ! bundle_is_verified "${work_dir}/${SCC_BUNDLE}"; then
    printf 'error: the SCC bundle does not match the pinned SHA-256\n' >&2
    exit 1
  fi
  mv "${work_dir}/${SCC_BUNDLE}" "${bundle}"
  printf 'downloaded and verified SCC %s from %s\n' "${SCC_VERSION}" "${SCC_BUNDLE_URL}"
fi

published_digests() {
  tr -d '\r' < "$1" | awk -v bundle="${SCC_BUNDLE}" '
    $0 == bundle { section = 1; next }
    section && /^ *=+ / { exit }
    section && $1 == "cscc" { want = "cscc"; next }
    section && /^SHA256:/ {
      if (!seen) { printf "bundle %s\n", $2; seen = 1 }
      else if (want == "cscc") { printf "cscc %s\n", $2; want = "" }
    }
  '
}

if fetch "${SCC_CHECKSUMS_URL}" "${work_dir}/checksums.txt" 1048576; then
  published="$(published_digests "${work_dir}/checksums.txt")"
  if [[ "${published}" != "bundle ${SCC_BUNDLE_SHA256}"$'\n'"cscc ${SCC_CSCC_SHA256}" ]]; then
    printf 'error: the published checksum file does not list the pinned digests of %s and cscc\n' "${SCC_BUNDLE}" >&2
    printf 'published: %s\n' "${published:-nothing}" >&2
    exit 1
  fi
  printf 'the published checksum file %s lists the pinned bundle and cscc digests\n' "${SCC_CHECKSUMS_URL}"
else
  printf 'warning: the published checksum file could not be fetched; relying on the reviewed pins only\n' >&2
fi

members="$(unzip -Z1 "${bundle}")"
if [[ "$(grep -cxF -- "${SCC_DEB_MEMBER}" <<<"${members}")" != '1' ]]; then
  printf 'error: the bundle does not contain exactly one %s\n' "${SCC_DEB_MEMBER}" >&2
  exit 1
fi
unzip -p "${bundle}" "${SCC_DEB_MEMBER}" > "${work_dir}/scc.deb"
if ! printf '%s  %s\n' "${SCC_DEB_SHA256}" "${work_dir}/scc.deb" | sha256sum --check --strict --quiet; then
  printf 'error: the Debian package in the bundle does not match the pinned SHA-256\n' >&2
  exit 1
fi

rm -rf "${context_dir}"
mkdir -p "${context_dir}"
install -m 0644 "${work_dir}/scc.deb" "${context_dir}/scc.deb"
printf 'staged the verified SCC %s Debian package in %s\n' "${SCC_VERSION}" "${context_dir}"
