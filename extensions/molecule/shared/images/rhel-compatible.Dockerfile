ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG OPENSCAP_SCANNER_VERSION=1:1.3.14-1.el9_8.rocky.0.1
ARG CRONIE_VERSION=1.5.7-16.el9
ARG OPENSSH_SERVER_VERSION=9.9p1-13.el9_8.rocky.0.1
ARG SUDO_VERSION=1.9.17p2-3.el9_8.3
ARG AUDIT_VERSION=3.1.5-8.el9
ARG KMOD_VERSION=28-11.el9
RUN dnf install --assumeyes --setopt=install_weak_deps=False \
        --setopt=retries=5 --setopt=timeout=20 --setopt=minrate=262144 \
        "openscap-scanner-${OPENSCAP_SCANNER_VERSION}" \
        "cronie-${CRONIE_VERSION}" \
        "openssh-server-${OPENSSH_SERVER_VERSION}" \
        "sudo-${SUDO_VERSION}" \
        "audit-${AUDIT_VERSION}" \
        "kmod-${KMOD_VERSION}" \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && ssh-keygen -A
