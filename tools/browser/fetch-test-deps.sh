#!/usr/bin/env bash
set -euo pipefail

readonly AXE_VERSION='4.14.0'
readonly AXE_TARBALL_SHA256='2277b0a3ef47af9b52497faa3e71598e86e0a0e5e6eb295207a5657ede4709af'
readonly AXE_TARBALL_NPM_SHA512='f564d9c448ec67b6f5dd31fc24f99b576cfc0876e5f34ff6866dd73c41b826035d40b2bcd480515e64b11df3003a44aa41e4714ffd1dc0d0f3d863a6df3ce971'
readonly AXE_SCRIPT_SHA256='20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878'
readonly AXE_URL="https://registry.npmjs.org/axe-core/-/axe-core-${AXE_VERSION}.tgz"
readonly SHELL_VERSION='156.0.8078.4'
readonly SHELL_ZIP_SHA256='c3e50596aef52c58f8fda3c6b3411c33d34c88b177b3ed1c2243359fd3b8ba20'
readonly SHELL_BINARY_SHA256='4fa61f0ba0b4f89b7bec242c32ca16d3bccf69dbfef0651924a9ba8fede5f9d6'
readonly SHELL_URL="https://storage.googleapis.com/chrome-for-testing-public/${SHELL_VERSION}/linux64/chrome-headless-shell-linux64.zip"
readonly SHELL_BINARY='chrome-headless-shell-linux64/chrome-headless-shell'

target_dir="${1:?usage: fetch-test-deps.sh <directory>}"
stamp="axe-core ${AXE_VERSION} ${AXE_TARBALL_SHA256} chrome-headless-shell ${SHELL_VERSION} ${SHELL_ZIP_SHA256}"

if [[ "$(uname -s)" != 'Linux' || "$(uname -m)" != 'x86_64' ]]; then
  printf 'error: the pinned test browser is only published for Linux x86_64\n' >&2
  exit 1
fi

verify_installed() {
  {
    printf '%s  %s\n' "${AXE_SCRIPT_SHA256}" "$1/axe.min.js"
    printf '%s  %s\n' "${SHELL_BINARY_SHA256}" "$1/${SHELL_BINARY}"
  } | sha256sum --check --strict --quiet
}

if [[ -f "${target_dir}/STAMP" && "$(cat "${target_dir}/STAMP")" == "${stamp}" ]]; then
  verify_installed "${target_dir}"
  printf 'browser test dependencies are present and verified in %s\n' "${target_dir}"
  exit 0
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

fetch() {
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$2" "$1"
}

fetch "${AXE_URL}" "${work_dir}/axe-core.tgz"
fetch "${SHELL_URL}" "${work_dir}/chrome-headless-shell.zip"
{
  printf '%s  %s\n' "${AXE_TARBALL_SHA256}" "${work_dir}/axe-core.tgz"
  printf '%s  %s\n' "${SHELL_ZIP_SHA256}" "${work_dir}/chrome-headless-shell.zip"
} | sha256sum --check --strict
printf '%s  %s\n' "${AXE_TARBALL_NPM_SHA512}" "${work_dir}/axe-core.tgz" | sha512sum --check --strict

mkdir -p "${work_dir}/axe"
tar -xzf "${work_dir}/axe-core.tgz" -C "${work_dir}/axe" package/axe.min.js package/LICENSE
unzip -q "${work_dir}/chrome-headless-shell.zip" -d "${work_dir}/shell"
mkdir -p "${work_dir}/install"
install -m 0644 "${work_dir}/axe/package/axe.min.js" "${work_dir}/install/axe.min.js"
install -m 0644 "${work_dir}/axe/package/LICENSE" "${work_dir}/install/axe-core.LICENSE"
mv "${work_dir}/shell/chrome-headless-shell-linux64" "${work_dir}/install/chrome-headless-shell-linux64"
verify_installed "${work_dir}/install"

installed_version="$("${work_dir}/install/${SHELL_BINARY}" --version)"
if [[ "${installed_version}" != "Google Chrome for Testing ${SHELL_VERSION}" ]]; then
  printf 'error: expected Chrome for Testing %s, found %s\n' "${SHELL_VERSION}" "${installed_version}" >&2
  exit 1
fi
printf '%s' "${stamp}" > "${work_dir}/install/STAMP"
rm -rf "${target_dir}"
mkdir -p "$(dirname "${target_dir}")"
mv "${work_dir}/install" "${target_dir}"
printf 'installed axe-core %s and %s into %s\n' "${AXE_VERSION}" "${installed_version}" "${target_dir}"
