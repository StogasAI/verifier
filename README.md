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
listening, and stops accepting new requests when the bundle expires.

The native verifier currently validates the live staging bundle. `serve` does not open its listener
yet: release is gated on integration tests proving that WebPKI and Stogas pin checks apply to the
same upstream TLS connection. Browser WASM publication is likewise gated on full Sigstore
cryptographic parity; the current community Rust Sigstore backend hard-depends on `aws-lc-rs`,
which does not target `wasm32-unknown-unknown`.

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

See [SECURITY.md](SECURITY.md) to report vulnerabilities.
