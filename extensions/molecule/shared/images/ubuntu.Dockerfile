ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG PYTHON3_VERSION=3.12.3-0ubuntu2.1
ARG OPENSCAP_SCANNER_VERSION=1.3.9+dfsg-1.1ubuntu2
ARG CRON_VERSION=3.0pl1-184ubuntu2
ARG PYTHON3_APT_VERSION=2.7.7ubuntu5.3
ARG LIBPAM_PWQUALITY_VERSION=1.4.5-3build1
ARG OPENSSH_SERVER_VERSION=1:9.6p1-3ubuntu13.20
ARG SUDO_VERSION=1.9.15p5-3ubuntu5.24.04.4
ARG KMOD_VERSION=31+20240202-2ubuntu7.2
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes \
        "python3=${PYTHON3_VERSION}" \
        "openscap-scanner=${OPENSCAP_SCANNER_VERSION}" \
        "cron=${CRON_VERSION}" \
        "python3-apt=${PYTHON3_APT_VERSION}" \
        "libpam-pwquality=${LIBPAM_PWQUALITY_VERSION}" \
        "openssh-server=${OPENSSH_SERVER_VERSION}" \
        "sudo=${SUDO_VERSION}" \
        "kmod=${KMOD_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p -m 0755 /run/sshd
