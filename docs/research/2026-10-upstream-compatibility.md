# Upstream Compatibility Research (October 2026)

Verified on 2026-10-25. Version numbers come from GitHub Releases/tags API, PyPI/npm JSON, Launchpad/Debian APIs and vendor docs fetched on that date. Anything that could not be confirmed is marked **UNVERIFIED**.

> **Decisions take precedence over this research.** Where a recommendation below conflicts with an accepted or
> proposed ADR, the ADR wins. In particular: ComplianceAsCode playbooks and Bash fixes are not used for remediation
> ([ADR 0003](../adr/0003-native-module-remediation.md)), and Trivy is not used at all
> ([ADR 0006](../adr/0006-toolchain-selection.md)).

## Summary of recommendations

| # | Area | Recommendation |
|---|------|----------------|
| 1 | Content source | Pin ComplianceAsCode/content **v0.1.82** (BSD-3-Clause). Use only the datastreams of the release zip, to audit; never ship or run its per-profile playbooks or Bash scripts ([ADR 0025](../adr/0025-own-ansible-remediation-only.md)); do not treat Ubuntu 26.04 as supported yet (only a hidden "default" profile). |
| 1 | Rocky/Alma | No Rocky product exists in SSG; AlmaLinux has `almalinux9` only (no Alma 10). Rocky/Alma 10 mapping is UNVERIFIED; plan to test the `rhel10` datastream against them and document the CPE caveat. |
| 2 | Scanner | OpenSCAP **1.4.6** upstream. Distros lag: Ubuntu 24.04 = 1.3.9, 26.04 = 1.4.3 (both universe), Debian 13 = 1.4.2, RHEL 10 = 1.4.3, RHEL 9 = 1.3.13. Support the 1.3 and 1.4 lines. Do not depend on Canonical USG (Ubuntu Pro). |
| 3 | Ansible | Target **ansible-core 2.21** (2.20 as floor for CI matrix); controller Python 3.12-3.14. `ansible-lint` 26.10.1. Sanity ignores live in `tests/sanity/ignore-X.Y.txt`. |
| 4 | Molecule | Molecule **26.10.0** with the ansible-native layout in `extensions/molecule/` (officially documented). Docker: use `community.docker` in your own create/destroy playbooks (no driver dependency). libvirt: no first-class driver; use `community.libvirt` in create/destroy playbooks. |
| 5 | Packer/AWS | Packer **1.16.2** (BUSL, not OSS). Plugins: amazon **1.8.3**, qemu **1.1.7**, ansible **1.1.6**. Build qcow2 on an ephemeral nested-virt EC2 instance (c8i/m8i/r8i or c7i etc.), not on CodeBuild. CodeBuild `/dev/kvm` is UNVERIFIED. |
| 6 | Alpine | **3.24.3**, python3 3.14.8, buildah 1.44.0 (community repo). Index digest below. |
| 7 | Tooling | See version table. Pin all GitHub Actions to SHAs; avoid Trivy 0.69.4+ era tags (March 2026 compromise). Prefer Trivy over the (non-archived but superseded) tfsec. |
| 8 | Registry | **GHCR as the canonical public registry**; push from GitHub Actions with `GITHUB_TOKEN`. If CodeBuild must build the toolbox, push to **ECR Public via IAM** and mirror/promote to GHCR from Actions. |
| 9 | GitHub | Team plan: repo-level rulesets, required checks, merge queue (public org-owned repos), Pages and attestations all work for public repos. **Org-level rulesets are Enterprise-only.** |
| 10 | OS lifecycle | Ubuntu 26.04 (released 2026-04-23), RHEL 10.2, Rocky/Alma 10.2, Debian 13.7 all GA with official cloud images and checksum files. |

---

## 1. ComplianceAsCode/content (SSG)

**Latest release: v0.1.82, published 2026-09-01.** Cadence is quarterly (0.1.81 on 2026-06-01, 0.1.80 on 2026-03-06). Source: <https://github.com/ComplianceAsCode/content/releases/tag/v0.1.82> (API: `gh api repos/ComplianceAsCode/content/releases`).
Implication: pin by tag and by the published `.sha512`; expect a ~3 month refresh cycle.

**Release assets** (`scap-security-guide-0.1.82.{zip,tar.gz,tar.bz2}` plus `.sha512` files): the zip contains `ssg-<product>-ds.xml` datastreams, `ansible/<product>-playbook-<profile>.yml` (284 files) and `bash/` remediation scripts. Source: asset list from the release above, contents inspected from the zip.
Implication: per-profile Ansible playbooks are shipped, but they are generated artifacts. Superseded by [ADR 0003](../adr/0003-native-module-remediation.md) and [ADR 0025](../adr/0025-own-ansible-remediation-only.md): the collection consumes only the datastreams, to audit, verifies the sha512, and never uses the playbooks, the Bash scripts, the `fix` elements or `oscap xccdf generate fix`.

**Licence:** BSD-3-Clause (LICENSE header "SPDX license identifier: BSD-3-Clause", Red Hat copyright). Source: <https://raw.githubusercontent.com/ComplianceAsCode/content/master/LICENSE>. (GitHub's API reports NOASSERTION only because of the SPDX header format.)
Implication: compatible with redistributing/wrapping in an Apache/GPL/MIT collection with attribution.

**Products and profiles (master, products/ directory and release zip):**

| Product | Profiles present | Notes |
|---|---|---|
| rhel9 | anssi_bp28_{minimal,intermediary,enhanced,high}, bsi, ccn_*, cis, cis_server_l1, cis_workstation_l1, cis_workstation_l2, cui, e8, hipaa, ism_o, ospp, pci-dss, stig, stig_gui | STIG updated to DISA V2R9 in 0.1.82 |
| rhel10 | anssi_bp28_* (all four), bsi, cis, cis_server_l1, cis_workstation_l1/l2, cui, e8, hipaa, ism_o(+secret/top_secret), ospp, pci-dss, stig, stig_gui | RHEL 10 STIG V1R2 |
| ubuntu2404 | cis_level1_server, cis_level1_workstation, cis_level2_server, cis_level2_workstation, stig | No ANSSI, OSPP or PCI-DSS |
| ubuntu2604 | only hidden `default` (minimal, "ensure benchmark generation") | Product added in 0.1.82; datastream shipped but no playbooks/CIS/STIG yet |
| debian12 | anssi_bp28_*, anssi_np_nt28_*, cis_level1/2_{server,workstation}, standard | |
| debian13 | anssi_bp28_*, cis_level1/2_{server,workstation}, standard | CIS Debian 13 controls added in 0.1.82 |
| almalinux9 | anssi_bp28_*, cis, cis_server_l1, cis_workstation_l1/l2, hipaa, pci-dss, standard, stig, stig_gui | **No almalinux10 product** |
| Rocky | **no product** | |

Sources: <https://github.com/ComplianceAsCode/content/tree/master/products> (and `/products/<product>/profiles`), release zip listing for v0.1.82.
Implications:

- Rocky/Alma: they do not reuse RHEL content out of the box in SSG; Alma 9 has its own product, Alma 10 and Rocky 9/10 have none. Whether the `rhel10` datastream evaluates correctly on Rocky/Alma 10 (CPE platform applicability on `redhat-release`) is **UNVERIFIED**; test it in Molecule before claiming support.
- Ubuntu 26.04: do not advertise CIS/STIG support until upstream adds profiles; ubuntu2404 is the only supported Ubuntu LTS for CIS/STIG.
- ANSSI BP-028 levels exist for RHEL 9/10 and Debian 12/13, not Ubuntu.
- OSPP exists for RHEL 9/10 only. PCI-DSS exists for RHEL 9/10 and Alma 9 only.

**CIS redistribution:** UNVERIFIED legally. SSG profiles are SSG's own rule implementations mapped to CIS recommendation numbers (BSD-3 code); I found no statement in the repo docs on CIS licensing (the User Guide page is deprecated and has no such text: <https://github.com/ComplianceAsCode/content/blob/master/docs/manual/user_guide.adoc>). For context, CIS Benchmark documents themselves are CC BY-NC-SA 4.0 and commercial use needs CIS approval (per NIST NCP mirrors: <https://ncp.nist.gov/checklist/revision/1555> and CIS blog <https://www.cisecurity.org/insights/blog/making-security-happen>).
Implication: do not copy CIS benchmark text/PDF descriptions into the repo; reference SSG rule IDs and CIS section numbers only, name profiles "aligned with CIS" and add a disclaimer; get a legal read if the project is commercial.

## 2. OpenSCAP and Ubuntu Security Guide

**Upstream OpenSCAP: 1.4.6, published 2026-10-22.** Source: <https://github.com/OpenSCAP/openscap/releases/tag/1.4.6>.
Implication: distro packages are all older; the collection must run against 1.3.x and 1.4.x.

**Distro packaging (verified via APIs):**

| Distro | Version | Source |
|---|---|---|
| Ubuntu 24.04 (noble) | 1.3.9+dfsg-1.1ubuntu2, `universe` | <https://api.launchpad.net/devel/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=openscap&exact_match=true> |
| Ubuntu 26.04 (resolute) | 1.4.3+dfsg-1ubuntu1 (updates), `universe` | same |
| Debian 12 (bookworm) | 1.3.7+dfsg-1+deb12u1 | <https://sources.debian.org/api/src/openscap/> |
| Debian 13 (trixie) | 1.4.2+dfsg-1 | same |
| RHEL 9 | 1.3.13 (release notes list 1.3.13 in 9.x.Z) | <https://access.redhat.com/articles/7047634> |
| RHEL 10 | 1.4.2 (10.0.Z), 1.4.3 (10.1.Z) | same |

Debian/Ubuntu packaging also carries `scap-security-guide` (SSG) in universe: Ubuntu 24.04 0.1.71, 26.04 0.1.79; Debian 13 0.1.76, sid 0.1.82 (Launchpad API above, <https://sources.debian.org/api/src/scap-security-guide/>). Binary package names (`openscap-scanner`, `openscap-utils`, `libopenscap8`, `ssg-base`, `ssg-debderived`) were not individually re-verified: **UNVERIFIED** for 26.04.
Implication: distro SSG is older than 0.1.82 and its Ubuntu/Debian content lacks recent profiles; ship/pin the SSG release tarball (checksum-verified) rather than relying on distro `ssg-*` packages. Known Ubuntu-specific OpenSCAP bugs: not researched, UNVERIFIED.

**Canonical Ubuntu Security Guide (USG):** its documentation installation flow is "install the Pro client, attach the subscription, enable USG"; the profile table covers 20.04, 22.04, 24.04 (CIS L1/L2 server/workstation and DISA-STIG); 26.04 is not listed. Source: <https://documentation.ubuntu.com/security/compliance/usg/>. Ubuntu Pro is free only for personal use up to 5 machines (50 for community members): <https://ubuntu.com/pricing/pro>.
Implication: USG needs an Ubuntu Pro entitlement, so the collection must not depend on it. Explicit statement of "USG licence terms" was not found: UNVERIFIED.

## 3. Ansible

- **ansible-core latest stable: 2.21.5 (2026-10-05)**, requires Python >=3.12 (PyPI <https://pypi.org/project/ansible-core/>). `ansible` community package 14.5.0 (bundles 2.21).
- **Support matrix** (<https://docs.ansible.com/projects/ansible/devel/reference_appendices/release_and_maintenance.html>):

| core | GA | EOL | Controller Python | Target Python |
|---|---|---|---|---|
| 2.22 | Nov 2026 (not released) | May 2028 | 3.13-3.15 | 3.9-3.15 |
| 2.21 | May 2026 | Nov 2027 | 3.12-3.14 | 3.9-3.14 |
| 2.20 | 2025-11-03 | May 2027 | 3.12-3.14 | 3.9-3.14 |
| 2.19 | 2025-07-21 | Nov 2026 | 3.11-3.13 | 3.8-3.13 |

Implication: set `requires_ansible: ">=2.20.0"` (2.19 is EOL in Nov 2026), CI matrix 2.20, 2.21 and devel/2.22. Targets such as RHEL 9 (Python 3.9) are still supported as target Python, but RHEL 8's 3.6 is not.

- **ansible-lint: 26.10.1 (2026-10-13)**, Python >=3.10 (<https://github.com/ansible/ansible-lint/releases>). Implication: pin in pre-commit/CI.
- **ansible-test sanity:** collection ignore files are `tests/sanity/ignore-X.Y.txt`, one per ansible-core version tested; tests that raise a traceback cannot be ignored. Source: <https://docs.ansible.com/projects/ansible/devel/dev_guide/testing/sanity/ignores.html>. Run with `ansible-test sanity --docker` from `ansible_collections/<ns>/<name>/` (<https://docs.ansible.com/projects/ansible/devel/dev_guide/testing_sanity.html>). Implication: keep ignore files empty/minimal; the project should have no ignores for a new collection.
- **Collection metadata:** `galaxy.yml` at root is the only required file; `meta/runtime.yml` with `requires_ansible` (PEP 440 specifier) is optional by the docs but needed in practice for Galaxy/certified tooling. Source: <https://docs.ansible.com/projects/ansible/devel/dev_guide/developing_collections_structure.html>. Exact required `galaxy.yml` fields (namespace, name, version, readme, authors) were not extracted from that page: UNVERIFIED, run `ansible-galaxy collection init`/`build` to confirm. Namespace `freesecdev` on Galaxy must be requested/claimed: not researched.

## 4. Molecule

- **Latest: molecule 26.10.0 (2026-10-12)**, Python >=3.10; raises minimum ansible-core to 2.16.19 (<https://github.com/ansible/molecule/releases/tag/v26.10.0>). `molecule-plugins` 26.10.12 (2026-10-12) (<https://pypi.org/project/molecule-plugins/>, <https://github.com/ansible-community/molecule-plugins>). Calver, monthly cadence.
- **Layout:** the official collection guide creates scenarios in `extensions/molecule/<scenario>/` plus shared `extensions/molecule/config.yml` and `inventory.yml`, via `ansible-creator init collection` (<https://github.com/ansible/molecule/blob/main/docs/getting-started-collections.md>). Yes, `extensions/molecule/` is the recommended location.
- **Ansible-native config** (no `driver:`/`platforms:` sections; `ansible.executor`, `ansible.playbooks.{create,destroy,converge,verify}`, `shared_state`, `verifier: ansible`) is the documented primary approach; the old driver/platforms/provisioner model is kept as "pre ansible-native" for compatibility (<https://github.com/ansible/molecule/blob/main/docs/ansible-native.md> and `pre-ansible-native.md`). Default driver remains "delegated" (installation.md).
- **Docker:** `molecule-plugins[docker]` still exists (driver `docker`, depends on `docker` Python SDK) but belongs to the legacy model. libvirt: `molecule-plugins` ships `vagrant` (needs `python-vagrant` + Vagrant + vagrant-libvirt) but **no dedicated libvirt driver** (pyproject.toml of molecule-plugins). `community.libvirt` collection latest 2.4.0 (2026-10-09).
- **Recommendation:** ansible-native layout in `extensions/molecule/`, with your own create/destroy playbooks: `community.docker.docker_container` for containers, `community.libvirt.virt`/cloud-init (or `libvirt_domain` via `community.libvirt`) for VMs. Avoid driver plugins so the test infra is the same Ansible you ship. The `vagrant` plugin is the fallback only if you accept Vagrant.
- Docker containers cannot test kernel/auditd/sysctl/FIPS/boot-time rules faithfully; use libvirt VMs for those (this is a content-correctness constraint, not a tool one).

## 5. Packer and qcow2 builds in AWS

- **Packer 1.16.2 (2026-10-22)**; license is BUSL 1.1 (IBM, "Packer Version 1.10.0 or later") (<https://github.com/hashicorp/packer>, LICENSE). Implication: fine to run in your own CI; note that OpenTofu-style forks do not exist for Packer, and BUSL forbids offering it as a competing hosted service.
- **Plugins:** `hashicorp/amazon` **v1.8.3** (2026-10-07; adds nested virtualization support in the EBS builder with instance-family checks); `hashicorp/qemu` **v1.1.7** (2026-09-30); `hashicorp/ansible` **v1.1.6** (2026-07-14). Sources: <https://github.com/hashicorp/packer-plugin-amazon/releases/tag/v1.8.3>, <https://github.com/hashicorp/packer-plugin-qemu/releases>, <https://github.com/hashicorp/packer-plugin-ansible/releases>.
- **`required_plugins`:** `packer init` downloads the matching zip and verifies it against the release `SHA256SUMS`; GitHub sources need a shasums file in the release; Packer does not authenticate to plugin sources (<https://developer.hashicorp.com/packer/docs/plugins/install-plugins>). A lockfile/hash pinning feature was not documented on that page: UNVERIFIED. Implication: pin exact versions (`= 1.8.3`), mirror/verify plugin binaries yourself in CI if reproducibility matters.
- **KVM on EC2:** nested virtualization on **non-metal** instances launched February 2026 (C8i/M8i/R8i), now supported on M7i, M7i-flex, M8i, M8id, M8i-flex, C7i, C7i-flex, C8i, C8id, C8i-flex, R7i, R7iz, R8i, R8id, R8i-flex, X8i, I7i, I7ie. Enable with `--cpu-options NestedVirtualization=enabled`; KVM and Hyper-V as L1; no extra cost; AWS still recommends bare metal for performance-sensitive work; Graviton not supported. Sources: <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html>, <https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-ec2-nested-virtualization-on-virtual>. A June 2026 announcement extended it to more Intel platforms and GovCloud (<https://aws.amazon.com/about-aws/whats-new/2026/06/nested-virtualization-intel-us-gov-cloud/>; details not fetched).
- **Cost (eu-west-1), third-party aggregator only, UNVERIFIED against AWS:** c8i-flex.large (2 vCPU/4 GiB) $0.096/h (https://www.devzero.io/instances/aws/c8i-flex.large); c8i.large $0.101/h on-demand, ~$0.044 spot (https://www.devzero.io/instances/aws/c8i.large). Metal pricing not looked up (UNVERIFIED; metal is an order of magnitude more). A larger size (4-8 vCPU) is more realistic for TCG-free qemu installs, still well under $1/h.
- **CodeBuild `/dev/kvm`:** no AWS documentation found stating CodeBuild exposes `/dev/kvm` or supports nested virt: **UNVERIFIED**. Do not design around it.
- **Recommended pipeline:** CodeBuild (OIDC/IAM role) runs `packer build` with `amazon-ebs`/`null` to launch an ephemeral nested-virt-enabled EC2 instance (c8i or m8i), which runs qemu/KVM against the official cloud image (qcow2), applies Ansible and uploads the qcow2 plus checksums/attestation to S3; instance is terminated by Packer. Alternatively use the `qemu` builder directly on that host. Use AMIs only where AMI output is wanted.

## 6. Alpine Linux

- **Latest stable: v3.24, point release 3.24.3**; branch date 2026-06-09, main repo supported until 2028-06-01. Sources: <https://alpinelinux.org/releases/>, <https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/latest-releases.yaml>.
- **Packages (v3.24):** python3 **3.14.8-r0** (main); buildah **1.44.0-r2**, crun 1.30.1, netavark 1.17.2, fuse-overlayfs 1.16, slirp4netns 1.3.3, passt 2026.05.26 (community). Source: APKINDEX at <https://dl-cdn.alpinelinux.org/alpine/v3.24/{main,community}/x86_64/APKINDEX.tar.gz>. For 3.23: python3 3.12.15, buildah 1.42.2.
- **Support caveat:** Alpine states the community repo "is supported until next stable release" (<https://alpinelinux.org/releases/>). Implication: buildah gets updates only on the current stable branch; rebuild the toolbox on each new Alpine stable (about every 6 months) and rely on automated digest bumps. Python 3.14 as default interpreter matches ansible-core 2.21 (controller 3.12-3.14).
- **Docker Hub digests (fetched 2026-10-25, OCI image index, all of `3.24`, `3.24.3`, `latest` identical):**
  `docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`
  (`3.24.0` tag is `sha256:a2d49ea6...c829f4`, older.) Index covers linux/amd64, arm (v6,v7), arm64, 386, ppc64le, riscv64, s390x. Source: registry-1.docker.io manifests API.
- **Rootless Buildah:** requires user namespaces plus `shadow-uidmap`/`newuidmap` subuid/subgid ranges (the `shadow-subids` package), `fuse-overlayfs` (or kernel overlay with unprivileged user-ns) or `vfs` storage, and `crun`. In AWS CodeBuild non-privileged containers, user namespaces and `/dev/fuse` availability are **UNVERIFIED**; test with `BUILDAH_ISOLATION=chroot` and `--storage-driver vfs` as a fallback. I did not verify these constraints against upstream Buildah docs in this session.

## 7. Security/CI tool versions

| Tool | Latest (2026-10-25) | Source |
|---|---|---|
| zizmor | 1.31.1 (2026-10-15) | <https://github.com/zizmorcore/zizmor/releases> |
| actionlint | 1.7.12 (2026-03-30) | <https://github.com/rhysd/actionlint/releases> |
| Trivy | 0.76.1 (2026-10-21) | <https://github.com/aquasecurity/trivy/releases> |
| trivy-action | 0.36.0 (2026-04-22) | <https://github.com/aquasecurity/trivy-action/releases> |
| Grype | 0.121.0 (2026-10-19) | <https://github.com/anchore/grype/releases> |
| Syft | 1.55.0 (2026-10-19) | <https://github.com/anchore/syft/releases> |
| cosign | 3.1.4 (2026-10-20) | <https://github.com/sigstore/cosign/releases> |
| hadolint | 2.15.1 (2026-07-31) | <https://github.com/hadolint/hadolint/releases> |
| checkov | 3.3.30 (2026-10-20) | <https://pypi.org/project/checkov/> |
| tfsec | superseded by Trivy (repo not archived per API; no release found) | <https://github.com/aquasecurity/tfsec> |
| gitleaks | 8.30.1 (2026-03-21) | <https://github.com/gitleaks/gitleaks/releases> |
| Bandit | 1.9.4 (2026-02-25) | <https://pypi.org/project/bandit/> |
| Ruff | 0.17.2 (2026-10-22) | <https://pypi.org/project/ruff/> |
| mypy | 2.4.0 | <https://pypi.org/project/mypy/> |
| Pyright | 1.1.414 (npm and GitHub release 2026-09-09) | <https://www.npmjs.com/package/pyright> |
| pylint | 4.1.3 (2026-10-11) | <https://pypi.org/project/pylint/> |
| yamllint | 1.38.0 (2026-01-13) | <https://pypi.org/project/yamllint/> |
| markdownlint-cli2 | 0.24.0 | <https://www.npmjs.com/package/markdownlint-cli2> |
| lychee | 0.24.2 (2026-05-01) | <https://github.com/lycheeverse/lychee/releases> |
| OpenTofu | 1.13.2 (2026-10-21) | <https://github.com/opentofu/opentofu/releases> |
| ShellCheck (extra) | 0.11.0 (2025-08-04) | <https://github.com/koalaman/shellcheck/releases> |
| actions/attest-build-provenance | 4.2.2 (same version of `actions/attest`) | <https://github.com/actions/attest-build-provenance> |

Implication: many tools release weekly; use Renovate/Dependabot with SHA pinning rather than hand-maintained versions. Pyright's version number looked low for the date; I confirmed it on both npm and GitHub, not further.

**Trivy supply-chain incident (verified):** On 2026-03-19 attackers force-pushed malicious code to 75 of 76 `trivy-action` tags, and the `setup-trivy` action and Trivy binary **v0.69.4** were malicious (CVE-2026-33634, GHSA-69fq-xp46-6x23); Docker Hub images 0.69.5 and 0.69.6 were pushed on 2026-03-22. Entry was a late-Feb GitHub Actions misconfiguration (`pull_request_target`), and incomplete credential rotation let the attacker return. Known-safe: Trivy v0.69.2/0.69.3, trivy-action v0.35.0, setup-trivy v0.2.6. Sources: <https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack>, <https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/>, <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23>, <https://nvd.nist.gov/vuln/detail/cve-2026-33634>, <https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/>. Wiz also reports a parallel KICS action compromise (not independently verified).
Implication: pin every action to a full commit SHA, verify cosign signatures/digests for downloaded binaries, never use mutable tags, and run zizmor to catch `pull_request_target` misuse. Consider Grype+Syft as a second scanner so one vendor compromise does not blind you. Other 2025-2026 incidents (e.g. tj-actions in 2025) were not researched here: UNVERIFIED.

## 8. Registry: GHCR vs ECR Public

- **GHCR:** usage is free for public packages (storage and bandwidth "currently free" with at least one month notice before change) (<https://docs.github.com/en/billing/concepts/product-billing/github-packages>). Anonymous pull rate limits are not documented there: UNVERIFIED. Publishing from Actions with `GITHUB_TOKEN` works and auto-links the package to the repo (<https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry>). I did not verify whether GitHub App installation tokens can push to GHCR from outside Actions: UNVERIFIED; the documented non-Actions path is a PAT, which is a long-lived secret.
- **ECR Public:** 50 GB storage always free; anonymous pulls 500 GB/month free per IP, 5 TB/month authenticated; transfer to AWS compute free; unauthenticated rate limit 1 pull/second/region (not adjustable), authenticated 10/s (<https://aws.amazon.com/ecr/pricing/>, <https://docs.aws.amazon.com/AmazonECR/latest/public/public-service-quotas.html>). Push uses IAM (CodeBuild role) with no stored secret.
- **Recommendation:** GHCR is the canonical public registry (users, attestations and `gh attestation verify` integrate best). Build the toolbox in whichever system the toolchain requires, but publish to GHCR from GitHub Actions (OIDC-less, `GITHUB_TOKEN`). If the build must be in AWS CodeBuild, push to ECR Public with IAM and have a GitHub Actions job copy by digest (`cosign copy`/`skopeo`/`crane`) to GHCR, then attest. This avoids any long-lived GitHub token in AWS.

## 9. GitHub (Team plan, public repos)

Verified from GitHub's docs source (github/docs `data/reusables/gated-features/*`, fetched via GitHub API):

- **Rulesets:** available in public repos on Free/Team and on Team/Enterprise private. **Org-wide rulesets are Enterprise-only** ("For organizations on the GitHub Enterprise plan, you can set up rulesets at the organization level"). Source: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets>. Required status checks are a rule type inside rulesets (not separately verified here).
- **Merge queue:** "available in any public repository owned by an organization, or in private repositories owned by organizations using GitHub Enterprise Cloud". So works for public repos under the FreeSecDev org on any plan. Source: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue>.
- **Artifact attestations:** available for all current plans on public repos only (private needs Enterprise Cloud). Public repos use the Sigstore public-good instance with a public transparency log; SLSA v1.0 Build L2, L3 via reusable workflows. `actions/attest-build-provenance` is at v4.2.2, equal to `actions/attest` v4.2.2; whether the former is deprecated in favour of `actions/attest` is UNVERIFIED. Sources: <https://docs.github.com/en/actions/concepts/security/artifact-attestations>, <https://github.com/actions/attest-build-provenance>.
- **Pages:** available for public repos on any plan; limits 1 GB site, soft 100 GB/month bandwidth (<https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits>).

Implication: Team plan is enough; replicate the ruleset per repo (via Terraform/OpenTofu or `gh api`) since org-wide rulesets are unavailable, and note Team is not even required for public-repo features.

## 10. OS lifecycle and images

| OS | Status (2026-10-25) | Source |
|---|---|---|
| Ubuntu 26.04 LTS "resolute" | Released 2026-04-23, status Supported | <https://api.launchpad.net/devel/ubuntu/resolute> |
| Ubuntu 24.04 LTS | Supported (released 2024-04-25) | <https://api.launchpad.net/devel/ubuntu/noble> |
| RHEL 10 | GA May 2025; **10.2 released 2026-05-20** with RHEL 9.8; full support to ~May 2030 (third-party figure, UNVERIFIED) | <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/10.2_release_notes/index> |
| Rocky Linux 10 | 10.2 (images dated 20260525) | <https://dl.rockylinux.org/pub/rocky/> |
| AlmaLinux 10 | 10.2 directory present | <https://repo.almalinux.org/almalinux/> |
| Debian 13 "trixie" | Stable, point release 13.7 (2026-09-12) | <https://deb.debian.org/debian/dists/trixie/Release> |
| Debian 12 "bookworm" | 12.15 (2026-07-11) | <https://deb.debian.org/debian/dists/bookworm/Release> |

**Container images (all HTTP 200 when probed):** `docker.io/library/ubuntu:26.04` (`sha256:c098726d...fb944`), `ubuntu:24.04`, `debian:13` (`sha256:4c252754...b308`), `debian:12`, `almalinux:10`, `rockylinux/rockylinux:10`; UBI 9/10 at `registry.access.redhat.com/ubi9|ubi10`; Rocky also on `quay.io/rockylinux/rockylinux`. RHEL proper is only available as UBI without a subscription; UBI lacks systemd/auditd defaults, so container tests cover only a rule subset.

**qcow2 cloud images and checksum files (all returned 200):**

- Ubuntu 26.04: <https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img> , `SHA256SUMS` in the same directory (24.04 analogous).
- Debian 13: <https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2> , `SHA512SUMS` same directory (Debian 12: `.../bookworm/latest/debian-12-genericcloud-amd64.qcow2`).
- Rocky 10: <https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2> , `CHECKSUM` same directory (Rocky 9 analogous).
- AlmaLinux 10: <https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-latest.x86_64.qcow2> , `CHECKSUM` same directory (Alma 9 analogous).
- RHEL 10 qcow2: requires a Red Hat account download; not publicly fetchable (UNVERIFIED, not probed).
Implication: use the `latest` aliases only to discover, then pin concrete dated files plus their checksums (and the signed checksum files, e.g. `SHA256SUMS.gpg` for Ubuntu) in Packer; the Rocky `CHECKSUM` file is BSD-style `SHA256 (file) = hash`, which Packer's `file_checksum_url` must handle.
