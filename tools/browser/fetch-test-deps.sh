#!/usr/bin/env bash
set -euo pipefail

readonly AXE_VERSION='4.14.0'
readonly AXE_TARBALL_SHA256='2277b0a3ef47af9b52497faa3e71598e86e0a0e5e6eb295207a5657ede4709af'
readonly AXE_SCRIPT_SHA256='20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878'
readonly AXE_URL="https://registry.npmjs.org/axe-core/-/axe-core-${AXE_VERSION}.tgz"
readonly SHELL_VERSION='156.0.8078.4'
readonly SHELL_ZIP_SHA256='c3e50596aef52c58f8fda3c6b3411c33d34c88b177b3ed1c2243359fd3b8ba20'
readonly SHELL_URL="https://cdn.playwright.dev/builds/cft/${SHELL_VERSION}/linux64/chrome-headless-shell-linux64.zip"

target_dir="${1:?usage: fetch-test-deps.sh <directory>}"
stamp="axe-core ${AXE_VERSION} ${AXE_TARBALL_SHA256} chrome-headless-shell ${SHELL_VERSION} ${SHELL_ZIP_SHA256}"

if [[ "$(uname -s)" != 'Linux' || "$(uname -m)" != 'x86_64' ]]; then
  printf 'error: the pinned test browser is only published for Linux x86_64\n' >&2
  exit 1
fi

if [[ -f "${target_dir}/STAMP" && "$(cat "${target_dir}/STAMP")" == "${stamp}" ]]; then
  printf '%s  %s\n' "${AXE_SCRIPT_SHA256}" "${target_dir}/axe.min.js" | sha256sum --check --strict --quiet
  printf 'browser test dependencies are present in %s\n' "${target_dir}"
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

mkdir -p "${work_dir}/axe"
tar -xzf "${work_dir}/axe-core.tgz" -C "${work_dir}/axe" package/axe.min.js package/LICENSE
printf '%s  %s\n' "${AXE_SCRIPT_SHA256}" "${work_dir}/axe/package/axe.min.js" | sha256sum --check --strict
unzip -q "${work_dir}/chrome-headless-shell.zip" -d "${work_dir}/shell"

rm -rf "${target_dir}"
mkdir -p "${target_dir}"
install -m 0644 "${work_dir}/axe/package/axe.min.js" "${target_dir}/axe.min.js"
install -m 0644 "${work_dir}/axe/package/LICENSE" "${target_dir}/axe-core.LICENSE"
mv "${work_dir}/shell/chrome-headless-shell-linux64" "${target_dir}/chrome-headless-shell-linux64"

installed_version="$("${target_dir}/chrome-headless-shell-linux64/chrome-headless-shell" --version)"
if [[ "${installed_version}" != "Google Chrome for Testing ${SHELL_VERSION}" ]]; then
  printf 'error: expected Chrome for Testing %s, found %s\n' "${SHELL_VERSION}" "${installed_version}" >&2
  exit 1
fi
printf '%s' "${stamp}" > "${target_dir}/STAMP"
printf 'installed axe-core %s and %s into %s\n' "${AXE_VERSION}" "${installed_version}" "${target_dir}"
