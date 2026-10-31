#!/usr/bin/env bash
set -euo pipefail

readonly CASES=/cases
readonly OUT=/out
readonly ORACLE=/oracle

work="$(mktemp -d)"

prepare_rhel() {
  installed="$(rpm -q --qf '%{VERSION}-%{RELEASE}' pam)"
  dnf install -y --setopt=install_weak_deps=False dnf-plugins-core rpm-build gcc glibc-devel patch cpio >/dev/null
  mkdir -p "${work}/srpm"
  dnf download --source --enablerepo=baseos-source --destdir "${work}/srpm" "pam-${installed}" >/dev/null 2>&1 \
    || dnf download --source --enablerepo=baseos-source --destdir "${work}/srpm" pam >/dev/null
  srpm="$(find "${work}/srpm" -name 'pam-*.src.rpm' | head -n 1)"
  source_version="$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "${srpm}" 2>/dev/null)"
  mkdir -p "${work}/rpmbuild/SOURCES" "${work}/rpmbuild/SPECS"
  (cd "${work}/rpmbuild/SOURCES" && rpm2cpio "${srpm}" | cpio -idm --quiet)
  mv "${work}/rpmbuild/SOURCES/pam.spec" "${work}/rpmbuild/SPECS/pam.spec"
  rpmbuild --define "_topdir ${work}/rpmbuild" -bp --nodeps "${work}/rpmbuild/SPECS/pam.spec" >"${work}/prep.log" 2>&1 || true
  if ! grep -q '^+ autoreconf' "${work}/prep.log"; then
    cat "${work}/prep.log" >&2
    printf 'error: the patches of %s were not all applied\n' "${srpm}" >&2
    exit 1
  fi
  src="$(find "${work}/rpmbuild/BUILD" -maxdepth 1 -type d -name 'Linux-PAM-*' | head -n 1)"
  config_dir="/etc/security"
}

prepare_debian() {
  installed="$(dpkg-query -W -f '${Version}' libpam-modules)"
  sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
  apt-get update >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev dpkg-dev >/dev/null
  mkdir -p "${work}/deb" && chmod 0777 "${work}/deb"
  (cd "${work}/deb" && apt-get source "pam=${installed}" >/dev/null 2>&1)
  source_version="${installed}"
  src="$(find "${work}/deb" -maxdepth 1 -type d -name 'pam-*' | head -n 1)"
  config_dir="/etc/security"
}

if command -v rpm >/dev/null 2>&1 && [[ -f /etc/redhat-release ]]; then
  platform=rhel_compatible
  prepare_rhel
elif command -v dpkg-query >/dev/null 2>&1; then
  platform=ubuntu
  prepare_debian
else
  printf 'error: unknown distribution\n' >&2
  exit 1
fi

if [[ -z "${src}" ]]; then
  printf 'error: no prepared pam source tree\n' >&2
  exit 1
fi

mkdir -p "${work}/include"
cat >"${work}/include/config.h" <<EOF
#define _GNU_SOURCE 1
#define HAVE_GETLINE 1
#define UNUSED __attribute__((unused))
#define SCONFIGDIR "${config_dir}"
#define PWHISTORY_HELPER "/nonexistent"
EOF

flags=(-std=gnu11 -O0 -w "-I${work}/include" "-I${src}/libpam/include" "-I${src}/libpam")
gcc "${flags[@]}" "-I${src}/modules/pam_faillock" -o "${work}/probe_faillock" \
  "${ORACLE}/probe_faillock.c" "${src}/modules/pam_faillock/faillock_config.c" "${ORACLE}/stubs.c" \
  -Wl,--unresolved-symbols=ignore-all
gcc "${flags[@]}" "-I${src}/modules/pam_pwhistory" -o "${work}/probe_pwhistory" \
  "${ORACLE}/probe_pwhistory.c" "${src}/modules/pam_pwhistory/pwhistory_config.c" \
  "${src}/libpam/pam_modutil_searchkey.c" "${ORACLE}/stubs.c" -Wl,--unresolved-symbols=ignore-all
stack_flags=(-DLIBPAM_COMPILE "-DDEFAULT_MODULE_PATH=\"/lib/security/\"")
if grep -q 'struct line_buffer' "${src}/libpam/pam_handlers.c"; then
  stack_flags+=(-DPAM_LINE_BUFFER)
fi
gcc "${flags[@]}" "${stack_flags[@]}" -o "${work}/probe_stack" "${ORACLE}/probe_stack.c" \
  "${src}/libpam/pam_misc.c" "${ORACLE}/stubs.c" -Wl,--unresolved-symbols=ignore-all

output="${OUT}/${platform}.jsonl"
printf '{"platform": "%s", "installed": "%s", "source": "%s"}\n' "${platform}" "${installed}" "${source_version}" >"${output}"
for case_dir in "${CASES}"/*/; do
  id="$(basename "${case_dir}")"
  reader="$(cat "${case_dir}/reader")"
  args=()
  while IFS= read -r arg || [[ -n "${arg}" ]]; do
    args+=("${arg//@conf/${case_dir}conf}")
  done <"${case_dir}/args"
  reading="$("${work}/probe_${reader}" "${args[@]}" 2>/dev/null)"
  if [[ -f "${case_dir}stack" ]]; then
    stack="$("${work}/probe_stack" "${case_dir}stack" 2>/dev/null)"
    printf '{"id": "%s", "reading": %s, "stack": %s}\n' "${id}" "${reading}" "${stack}" >>"${output}"
  else
    printf '{"id": "%s", "reading": %s}\n' "${id}" "${reading}" >>"${output}"
  fi
done
