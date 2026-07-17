# Stogas Verifier

Offline verification for the signed Stogas confidential-gateway trust bundle.

This repository contains one deterministic Rust verification engine and thin CLI, WebAssembly,
Python, Go, and C ABI adapters. The adapters capture the platform clock and persist opaque verifier
state; all security policy remains in the Rust core. No adapter performs network access during a
verification pass.

The project is pre-1.0 and must not be treated as independently security-reviewed yet.

## Packages

- `stogas-offline-sigstore`: networkless verification of the supported GitHub/Sigstore in-toto
  profile.
- `stogas-verifier`: atomic verification of `stogas.confidential-bundle.v1`.
- `stogas-verify`: offline verifier and optional loopback OpenAI-compatible proxy.

## CLI

```console
stogas-verify verify bundle.json
stogas-verify verify - --json --no-store
stogas-verify serve
```

`verify` never accesses the network. `serve` fetches a signed bundle, verifies it completely before
listening, and stops accepting new requests when the bundle expires. Its upstream connection first
passes normal WebPKI and hostname verification, then requires both the leaf-certificate hash and
the DER SubjectPublicKeyInfo SHA-256 to match the same verified node. Either certificate in that
node's signed two-slot rotation stack is accepted. Pinning is performed by the verifier attached to
the actual TLS connection; it is not a preliminary probe.

The native verifier currently validates the live staging bundle. Browser publication remains gated
on full Sigstore cryptographic parity. The complete AMD SNP certificate, RSA-PSS CRL, report
signature, Ed25519, and drand paths compile to `wasm32-unknown-unknown` using RustCrypto without
OpenSSL, `ring`, or AWS-LC. The remaining modular community Sigstore backend hard-depends on
`aws-lc-rs`; the WASM adapter therefore still rejects Sigstore verification rather than omitting
Fulcio, SCT, Rekor, checkpoint, timestamp, or DSSE checks.

The standard bundle endpoints are deliberately independent from the confidential API:

- staging: `https://evidence-staging.stogas.ai/bundles/latest.json`
- production: `https://evidence.stogas.ai/bundles/latest.json`

Each hostname is a direct public, read-only custom domain for its R2 bucket. Keeping evidence on a
separate origin lets clients recover and verify trust material while the API fleet or its load
balancer is unavailable. Browser SDKs require an R2 CORS rule for the application origins which
consume the verifier; native SDKs and the CLI do not.

## Security boundary

Bundle bytes, attestations, certificates, SNP reports, drand beacons, and persisted state are
untrusted. Verification is all-or-nothing: a failed release or node rejects the entire bundle and
does not advance rollback state. The C ABI accepts bounded byte buffers and exposes no cryptographic
primitive.

## Sigstore trust bootstrap

The Sigstore TUF root and trusted-root targets are public verification metadata, not secrets. The
native package pins the exact modular Sigstore Rust release and embeds its versioned production
trusted-root snapshot. Verification never contacts TUF, Fulcio, Rekor, or GitHub. Updating roots is
an explicit package release validated against real GitHub fixtures, `gh attestation verify`, and
`sigstore-go`; cached verification never extends a signed bundle deadline.

Tinfoil's verifier informed the narrow-profile defenses here: one DSSE signature, one Rekor entry,
one SCT, exact subjects, and independently pinned GitHub identity. Stogas keeps these checks in one
Rust policy core instead of maintaining separate native and browser policy implementations. The
browser implementation will use a WASM-compatible audited cryptographic backend and will not omit
Fulcio, SCT, Rekor inclusion, checkpoint, timestamp, or DSSE validation to reduce bundle size.

## Continuous integration

Every pull request and push to `main` runs:

- formatting and warning-free Clippy on Ubuntu x86-64;
- the complete native workspace test suite on Linux x86-64, Linux ARM64, macOS ARM64, macOS
  x86-64, and Windows x86-64;
- a browser dependency gate which rejects OpenSSL, `ring`, and AWS-LC, then compiles the real SNP
  feature set for `wasm32-unknown-unknown`.

Compilation is not browser verification conformance. npm/WASM publication remains blocked until
the real GitHub fixture and mutation suite execute in a network-disabled browser and produce the
same result, error category, and rollback state as the native verifier.

## Historical evidence

Clients never search Rekor or a Stogas archive to accept a current node. The signed bundle is
self-contained. Rekor is used for the GitHub release attestation it was designed to record; it is
not a fleet database and Stogas does not submit per-heartbeat or per-node identity records to it.

Long-term fleet audit material belongs in immutable, sequence-addressed Stogas bundle archives. If
independent non-equivocation evidence is later required, Stogas can publish signed bundle-hash
checkpoints to one or more transparency witnesses without making those witnesses part of runtime
verification.

See [SECURITY.md](SECURITY.md) to report vulnerabilities.
