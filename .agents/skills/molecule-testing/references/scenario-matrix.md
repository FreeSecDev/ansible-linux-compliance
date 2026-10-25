# Scenario matrix

| Scenario | Driver | Purpose |
|---|---|---|
| `docker-ubuntu` | community.docker | Fast role and module checks on Ubuntu |
| `docker-rhel-compatible` | community.docker | Fast checks on a RHEL-compatible image |
| `libvirt-ubuntu-bare` | community.libvirt | Full VM from a bare cloud image, Ubuntu |
| `libvirt-rhel-bare` | community.libvirt | Full VM from a bare cloud image, RHEL-compatible |
| `libvirt-negative` | community.libvirt | Invalid profile, unavailable scanner, bad arguments |
| `libvirt-idempotency` | community.libvirt | Repeated converge, zero unexpected changes |
| `libvirt-ubuntu-golden` | community.libvirt | Golden image from the manifest, Ubuntu |
| `libvirt-rhel-golden` | community.libvirt | Golden image from the manifest, RHEL-compatible |
| `libvirt-baseline-regression` | community.libvirt | Compare findings with the recorded baseline |
| `libvirt-remediation` | community.libvirt | Opt-in remediation then verify |

The final layout is confirmed by ADR.

## Per-run checklist

1. Resolve images by digest or manifest SHA-256 and verify.
2. Generate unique names and an ephemeral key.
3. Create the isolated NAT network and instances.
4. Run the localhost guard before any converge.
5. Converge, then idempotence with volatility normalization.
6. Verify, scan, assert expected findings.
7. Check mode, diff mode and audit-only assertions.
8. Destroy in an always-run block, then confirm nothing is left.

## Container-only limits

Mark and skip in containers: bootloader, mounts, kernel parameters, services requiring systemd as PID 1, firewall. Run them in libvirt.
