#!/usr/bin/env bash
set -euo pipefail

readonly TOFU_VERSION='1.13.2'
readonly SHA256_LINUX_AMD64='ac05d9952662c7db28dd57e93f0a68018837bfdf9342384ec0987977c16a9645'
readonly SHA256_LINUX_ARM64='88e2d9e3f94f97b76ab2faf55ade87578f56aed19c5e45fa139d70e994366d1f'
readonly RELEASE_URL="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}"

install_dir="${1:-${HOME}/.local/bin}"

case "$(uname -m)" in
  x86_64) architecture='amd64'; expected_sha256="${SHA256_LINUX_AMD64}" ;;
  aarch64 | arm64) architecture='arm64'; expected_sha256="${SHA256_LINUX_ARM64}" ;;
  *) printf 'error: unsupported architecture %s\n' "$(uname -m)" >&2; exit 1 ;;
esac

archive="tofu_${TOFU_VERSION}_linux_${architecture}.tar.gz"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "${work_dir}/${archive}" "${RELEASE_URL}/${archive}"

printf '%s  %s\n' "${expected_sha256}" "${archive}" > "${work_dir}/expected.sha256"
(cd "${work_dir}" && sha256sum --check --strict expected.sha256)

tar -xzf "${work_dir}/${archive}" -C "${work_dir}" tofu
mkdir -p "${install_dir}"
install -m 0755 "${work_dir}/tofu" "${install_dir}/tofu"

version_output="$("${install_dir}/tofu" version)"
installed_version="${version_output%%$'\n'*}"
printf 'installed %s to %s\n' "${installed_version}" "${install_dir}"
if [[ "${installed_version}" != "OpenTofu v${TOFU_VERSION}" ]]; then
  printf 'error: expected OpenTofu v%s\n' "${TOFU_VERSION}" >&2
  exit 1
fi

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "${install_dir}" >> "${GITHUB_PATH}"
fi
