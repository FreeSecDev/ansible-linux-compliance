# Architecture decision records

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | accepted |
| [0002](0002-documentation-in-git.md) | Documentation in Git instead of Confluence | accepted |
| [0003](0003-native-module-remediation.md) | Native-module remediation keyed by ComplianceAsCode rule identifiers | proposed |
| [0004](0004-audited-process-execution.md) | Single audited helper for external process execution | proposed |
| [0005](0005-renovate-version-annotations.md) | Version annotations on pinned GitHub Actions (amended for pre-commit revisions) | accepted |
| [0006](0006-toolchain-selection.md) | Toolchain selection for infrastructure and supply-chain security | proposed |
| [0007](0007-registry-build-and-signing.md) | Container registry, build location and signing | proposed |
| [0008](0008-qcow2-builds-nested-virtualization.md) | Portable qcow2 image builds on ephemeral nested-virtualization EC2 | proposed |
| [0009](0009-molecule-layout-and-drivers.md) | Molecule layout and drivers | proposed |
| [0010](0010-initial-os-and-benchmark-scope.md) | Initial operating system and benchmark scope | proposed |
| [0011](0011-control-toggles-and-cleanup.md) | Per-rule and per-topic control toggles with cleanup on disable | proposed |
| [0012](0012-github-native-releases-and-packages.md) | GitHub-native releases, packages and supply-chain features | proposed |
| [0013](0013-normalized-findings-model.md) | Normalized compliance findings model | accepted |
| [0015](0015-content-acquisition-and-pinning.md) | Content acquisition and pinning | proposed |
| [0014](0014-aws-account-bootstrap.md) | AWS account bootstrap | proposed |
| [0016](0016-report-schema-and-summary-semantics.md) | Report schema and summary semantics | proposed |
| [0017](0017-offline-html-dashboard.md) | Offline single-file HTML dashboard | proposed |
| [0018](0018-evidence-bundle-provenance.md) | Signed evidence bundles and verified report inputs | proposed |
| [0019](0019-scc-scanner-backend-and-ci-image.md) | SCAP Compliance Checker as a second scanner backend, with a CI-only image | proposed |
| [0020](0020-stig-viewer-checklist-export.md) | STIG Viewer checklist export (CKL and CKLB) | proposed |
| [0021](0021-native-banners-pwquality-and-profile-values.md) | Native banners and password quality, with profile values from the pinned content | proposed |
| [0022](0022-native-sudo-drop-ins.md) | Native sudo remediation through validated drop-ins | proposed |
| [0023](0023-native-ssh-server-configuration.md) | Native SSH server configuration through validated drop-ins | proposed |
| [0024](0024-native-login-defs.md) | Native login.defs remediation, one recorded line per setting | proposed |
| [0030](0030-native-auditd-settings-and-audit-rules.md) | Native auditd settings and audit rule drop-ins | proposed |

Proposed ADRs are accepted through the pull request that introduces their first implementation.
