ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG PYTHON3_VERSION=3.12.3-0ubuntu2.1
ARG OPENSCAP_SCANNER_VERSION=1.3.9+dfsg-1.1ubuntu2
ARG CRON_VERSION=3.0pl1-184ubuntu2
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes \
        "python3=${PYTHON3_VERSION}" \
        "openscap-scanner=${OPENSCAP_SCANNER_VERSION}" \
        "cron=${CRON_VERSION}" \
    && rm -rf /var/lib/apt/lists/*
