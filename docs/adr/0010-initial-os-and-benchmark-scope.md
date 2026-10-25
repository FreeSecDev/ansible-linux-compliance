# 0010. Initial operating system and benchmark scope

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending
- **Pull requests:** pending
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

## Context

ComplianceAsCode v0.1.82 provides CIS, STIG, OSPP, PCI DSS and ANSSI BP-028 profiles for RHEL 9 and 10.
It provides CIS and STIG for Ubuntu 24.04, and CIS and ANSSI for Debian 12 and 13. Ubuntu 26.04 has only a
hidden default profile. There is no Rocky Linux product and no AlmaLinux 10 product.

## Decision

The first fully implemented path is Ubuntu 24.04 with the ComplianceAsCode CIS Level 1 Server profile.
RHEL 9-compatible follows with CIS and STIG. Rocky and AlmaLinux are listed as "RHEL datastream, unverified" until
tests prove the RHEL content evaluates correctly on them. Ubuntu 26.04 is listed as "no benchmark content" and is
never audited against a different release's content. The support matrix records only executed tests.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| RHEL 9 first | Fewer free test images; Ubuntu cloud images are freely redistributable |
| Use ubuntu2404 content on 26.04 | Silent benchmark substitution |
| Claim Rocky support from RHEL content | Untested claim |

## Benefits

An honest, testable first milestone with freely available images.

## Trade-offs

ANSSI coverage starts on Debian and RHEL, not Ubuntu.

## Security implications

Prevents false assurance from mismatched content.

## Operational consequences

The support matrix and dashboard show unsupported combinations explicitly.
