# 0018. Signed evidence bundles and verified report inputs

- **Status:** proposed
- **Date:** 2026-10-26
- **Deciders:** lead architect
- **Jira:** FREES-130 (design), FREES-51 (evidence bundles, implementation), FREES-140 (signing)
- **Pull requests:** design introduced by the pull request for FREES-130 and FREES-132. The pull request for FREES-51
  implements the unsigned bundle of section 1 and nothing else; signing, verification and the `provenance` label are
  not implemented (see the [status update](#status-update-2026-10-26-frees-51)).
- **Related:** [ADR 0007](0007-registry-build-and-signing.md), [ADR 0012](0012-github-native-releases-and-packages.md),
  [ADR 0013](0013-normalized-findings-model.md), [ADR 0016](0016-report-schema-and-summary-semantics.md)

## Context

Every input of `make report` is a file that the operator supplies. Nothing proves where it came from. A ScanRun names
its host and machine ID, and an XCCDF or ARF file names its target, but all of these are written by the scanned host
or by whoever produced the file. A machine ID is not a secret. The FREES-75 review showed that a forged ScanRun with
the identity of a real host could raise that host's figure from 0.0 to 99.0 percent: the forgery adds passing rules
that the real run did not evaluate, and the report merged both runs rule by rule.

The report schema 2.0 ([ADR 0016, amendment of FREES-130](0016-report-schema-and-summary-semantics.md)) makes every
merge visible and refuses repeated scans unless the operator asks for them. That shows a forgery; it does not detect
one. An exceptions evaluation is verified against its own content, but the SHA-256 of the exceptions file it names is
taken as given. To tell a genuine input from a forged one the report needs evidence that is bound to an identity that
the attacker does not control.

FREES-51 introduces evidence bundles: the raw scanner output, the ScanRun JSON, checksums and provenance of one audit
run. They are the natural unit to sign.

## Decision (proposed)

### 1. One signed statement per evidence bundle

An evidence bundle is a directory (or a tarball of it) with a manifest `bundle.json` that lists every file with its
path, size and SHA-256, and records the run ID, the inventory host name, the benchmark, profile and content version,
the content digest that the content manifest verified (ADR 0015) and the collection version.

The controller signs the bundle with a [Sigstore](https://www.sigstore.dev/) attestation: an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) whose `subject` is every
file of the manifest (name and SHA-256) plus the manifest itself, with a project predicate type
`https://freesecdev.github.io/linux-compliance/evidence/v1` that repeats the run identity above. It is signed with
cosign (`cosign attest-blob`) and stored next to the bundle as a Sigstore bundle (`bundle.sigstore.json`) that
contains the signature, the certificate and the Rekor transparency log entry.

- **Keyless in CI.** Runs in GitHub Actions or AWS CodeBuild sign keyless through OIDC (Fulcio certificate for the
  workflow identity), exactly like images and releases (ADR 0007, ADR 0012). The certificate identity
  (`https://github.com/FreeSecDev/<repository>/.github/workflows/<file>@refs/heads/main`) and issuer are the trust
  anchor.
- **Key-based outside CI.** Operators who run audits from their own controller sign with a cosign key pair that they
  manage (KMS key or hardware token, never a key file in Git). The public key is part of the report invocation.
- **Offline.** A verifier can check a Sigstore bundle without network access when it pins the Sigstore trusted root
  (`trusted_root.json`) in the repository and updates it deliberately, like other pinned dependencies.

The signer is the controller, not the managed host. A compromised managed host can still lie in the scanner output it
returns; the signature proves which controller run collected the evidence and that nothing changed afterwards. This is
stated in the report and the documentation, so "verified" never reads as "the host is honest".

### 2. Verification in `make report`

`tools/reporting` gains a verification step that runs before parsing:

- A new option `--trust-policy FILE` names a YAML policy with the accepted signer identities: certificate identity and
  issuer for keyless signatures, or public keys, and optionally the inventory hosts each signer may speak for.
- An input supplied as part of an evidence bundle (`--evidence-bundle DIR`) is verified with the policy: the Sigstore
  bundle must verify (signature, certificate chain to the pinned root, Rekor inclusion proof, certificate identity in
  the policy), the statement subject must list the exact SHA-256 of every file the report reads, and the predicate
  must match the parsed content (run ID, host, benchmark, profile, content version, content digest).
- Verification uses `sigstore-python` (a pinned, hash-locked development and runtime dependency of the controller-side
  reporting package only) or the pinned `cosign` binary through the audited process helper; the choice is made in the
  implementation pull request after a dependency review. Nothing on the managed hosts changes.

### 3. Every input is labelled `verified` or `self_asserted`

The report schema gains one field per artifact reference, `provenance`, with the values:

| Value | Meaning |
|---|---|
| `verified` | The file is listed in an evidence bundle whose signature verified against the trust policy, and the predicate matches the parsed content |
| `self_asserted` | No signature was supplied, or the input format has none (XCCDF and ARF files supplied directly, test and build reports) |

A file whose signature was supplied but does not verify is an input `error`, never `self_asserted`: a broken signature
must not silently downgrade to "unsigned". `provenance` also appears on compliance groups (the group is `verified` only
when every input is) and in the `merged_inputs` notes. Figures do not change with provenance; the label is shown next to
them. A later decision may let an operator require `verified` inputs (`--require-verified`), which turns every
`self_asserted` compliance input into an error.

Adding `provenance` is a field addition and bumps the report schema minor version (2.1) under ADR 0016.

### 4. Exceptions files and evaluations

The exceptions file is configuration from Git; its authority is the reviewed pull request. An evaluation names the
SHA-256 of the file. With a trust policy, the controller run that applies the exceptions includes the exceptions file
and the evaluation documents in the evidence bundle, so the attestation binds the evaluation to the exact file. Without
it, the report labels the exceptions section `self_asserted` as well.

## Alternatives evaluated

| Alternative | Reason not proposed |
|---|---|
| Sign on the managed host | The host is the party whose claims need checking; a compromised host would sign its own lies, and target-side code may only use the standard library |
| GPG detached signatures per file | No transparency log, key distribution by hand, and one signature per file instead of one statement per run |
| HMAC with a shared secret | A secret on every controller and in CI; anyone who can verify can also forge |
| Trust the CI artifact store (for example GitHub artifact retention) | Proves nothing once a file leaves the store, and does not cover operators who run audits outside CI |
| GitHub artifact attestations only (`actions/attest`) | Suitable for CI runs and built on the same Sigstore format, so it can be the CI signer; it does not cover controllers outside GitHub, so the verifier must accept cosign keys as well |
| Refuse every unsigned input | Breaks every existing workflow and every format that has no signing story (JUnit, SARIF, Grype); a label first, an opt-in requirement later |

## Benefits

A forged or edited ScanRun or XCCDF file can be told apart from evidence that a known controller run collected, and the
report says which is which. Signing reuses the toolchain and trust anchors already chosen for images and releases.

## Trade-offs

- Signing needs network access to Fulcio and Rekor in CI, or a managed key outside it.
- Offline verification requires a pinned trusted root that must be updated deliberately.
- The signature binds the evidence to a controller run, not to the honesty of the scanned host.
- A new runtime dependency for the reporting package (`sigstore-python`) or a pinned `cosign` binary.

## Security implications

The trust policy becomes security configuration: who may sign evidence for which hosts. It belongs in Git with the
same review rules as the inventory and the exceptions file. Verification failures are errors, never downgrades. Rekor
entries are public: the predicate must not contain secrets or host evidence beyond identifiers (run ID, inventory
host, benchmark, profile, versions, digests); file contents stay out of the log.

## Operational consequences

- FREES-51 implements the bundle manifest and signing; a follow-up issue implements verification and the
  `provenance` field in `tools/reporting`.
- The dashboard shows `verified` and `self_asserted` beside every input and group, in a neutral tone for
  `self_asserted`, like the machine ID today.
- This ADR becomes accepted with the first implementation pull request; until then the report labels nothing as
  verified.

## Status update 2026-10-26 (FREES-51)

The status stays **proposed**. FREES-51 implements the evidence bundle without a signature
([evidence bundles](../evidence.md)); signing was evaluated for that pull request and is not feasible yet.

### What is implemented

- **The bundle of section 1, unsigned.** One directory per audit run and host, `<output>/<inventory host>/<run_id>`,
  with `bundle.json` (format `1.0`), `SHA256SUMS`, the raw scan run, the XCCDF results and the tailoring file and,
  when exceptions were applied, the evaluation, the exceptions file and the stale result (section 4). The manifest
  lists every file with its path, kind, size, SHA-256 and source and records the run ID, the inventory host, the
  machine ID of the facts, the host identity the scan run reports, the benchmark, profile, scanner, content source,
  version and digest, the exceptions file digest and the collection version: the identity that section 1 asks the
  predicate to repeat. The ARF results are excluded by default because they can hold credential material.
- **Checks when collecting.** Every fetched file must have the digest the audit recorded on the host, the evaluation
  must verify against the byte-exact exceptions file and must have been made from the raw scan run; a mismatch fails
  closed and leaves no bundle.
- **Report input.** `--evidence-bundle DIR` reads a bundle without following links and verifies the manifest, every
  digest, `SHA256SUMS`, the scan run against the manifest and the evaluation against the bundled exceptions file and
  the raw scan run. A bundle that fails is an input `error`.
- **No label.** The report schema is unchanged (2.0) and has no `provenance` field, so no input is labelled
  `verified`. A file in a bundle that looks like a signature (`*.sigstore.json`, `*.sig`, `*.pem`, `*.intoto.jsonl`,
  ...) is refused as an input error, so a signature that cannot be verified never reads as an unsigned bundle (the
  rule of section 3).

A verified bundle is consistent, not authentic: whoever can write the directory can rewrite every file and every
digest consistently. The bundle detects accidental change and partial edits, not deliberate forgery.

### What blocks signing

1. **No pinned signer where audits run.** `cosign` (or `sigstore-python`) is not part of the locked development
   environment or of any controller requirement. The role cannot run it: `ansible.builtin.command` is banned
   (AGENTS.md rule 1), so signing needs a new controller-side module or action plugin that runs a pinned, hash-verified
   `cosign` through the audited process helper (ADR 0004, a resolved absolute path in a trusted root-owned directory),
   and a way to install that binary on operator controllers. Action plugins import `ansible.plugins`, which the
   repository guard does not allow in `plugins/` today. Each of these is its own reviewed change.
2. **No signing identity for the runs that matter.** Keyless signing needs an OIDC token at collection time. Audits of
   real hosts run on operator controllers, which have no workflow identity. The only runs of the role in CI collect
   synthetic fixtures on the runner (`make test-evidence`), so a keyless CI signature would attest synthetic data and
   prove nothing about a host. Key-based signing needs a managed key (an AWS KMS key reached through the OIDC role of
   ADR 0014, or a hardware token), and none is provisioned: `infra/account` has no signing key.
3. **The public log would publish inventory names.** Section 1 puts the inventory host and run ID in the predicate,
   and keyless signatures are logged in the public Rekor instance. Publishing inventory host names and run times needs
   a decision (a private transparency log, or key-based signatures without a log entry, which loses the inclusion proof
   that section 2 verifies). The security implications above only cover file contents.
4. **No reviewed verifier and no report field.** Verification needs `sigstore-python` or a pinned `cosign` after a
   dependency review, a pinned `trusted_root.json`, the trust policy format of section 2, the `provenance` field
   (report schema 2.1 under ADR 0016) and the dashboard label. Adding the field before a verifier exists would only
   ever say `self_asserted`.

### What signing will add

The bundle layout does not change: the signature is one more file next to `bundle.json`, over the manifest (which
already lists every file's SHA-256), with the in-toto subject set of section 1. Readers of format `1.0` refuse that
file today; the version that verifies it accepts it. This ADR becomes accepted with that pull request. Follow-up:
FREES-140 (signing and verification).

## References

- Sigstore bundle format: <https://docs.sigstore.dev/about/bundle/>
- cosign blob attestations: <https://docs.sigstore.dev/cosign/verifying/attestation/>
- in-toto attestation framework: <https://github.com/in-toto/attestation>
