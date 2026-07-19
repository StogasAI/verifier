# Stogas Verifier

Offline verification for Stogas confidential-gateway evidence.

One Rust implementation powers the CLI, Rust, browser WebAssembly, Node, Bun, Python, Go, and C packages. Verification performs no network requests and writes no persistent state.

## Quick start

Verify a downloaded bundle:

```console
stogas-verify verify bundle.json
```

Or run a verified loopback OpenAI-compatible endpoint:

```console
stogas-verify serve
```

`serve` fetches a bundle before listening on `127.0.0.1:8787`, refreshes with jitter before verified bundle expiry, and atomically activates only a completely verified replacement. The upstream connection must pass normal WebPKI and hostname verification. Its certificate hash and SPKI must then match the same attested node.

## Packages

- `stogas-verifier`: complete Rust bundle verifier.
- `stogas-verify`: native CLI and loopback proxy.
- `@stogas/verifier`: browser, Worker, Node, and Bun WebAssembly package.
- `stogas-verifier` for Python: PyO3 `abi3-py310` native wheels.
- `github.com/StogasAI/verifier/go`: thin cgo binding.
- `stogas_verifier.h`: bounded C ABI.
- `stogas-offline-sigstore` and `@stogas/offline-sigstore`: generic verification for the supported GitHub/Sigstore profile.

The CLI is a native Rust application. WebAssembly is used by JavaScript environments and by the Stogas Control Worker, not by the native CLI.

## Verification result

The complete verifier checks:

- GitHub/Sigstore provenance and the Stogas signature over the same gateway launch policy;
- AMD SEV-SNP certificate paths, revocation data, report signatures, chip/TCB values, and launch measurement;
- report-data bindings for TLS, certificate rotation, HPKE, and Ed25519 keys;
- drand Quicknet identity, BLS signature, randomness, round time, and freshness;
- bundle, certificate, collateral, and evidence deadlines.

Nodes enter the returned trust set only when their evidence remains within the caller's freshness policy through verified bundle expiry. Older valid records are returned under `excluded_nodes`.

## SDK boundary

SDKs verify caller-provided bytes and return verified releases, nodes, exclusions, and bundle timestamps. A reusable verifier caches immutable release verification in memory. Explicit-time methods support deterministic tests and audits.

SDKs do not fetch bundles, schedule background work, persist state, or replace an application's HTTP stack. Use `stogas-verify serve` when managed refresh and TLS pinning should be handled out of process. Browser APIs do not expose the peer certificate needed for connection pinning.

## Sigstore profile

`stogas-offline-sigstore` supports the GitHub `actions/attest` v0.3 DSSE/in-toto SLSA profile used by gateway releases. It verifies Fulcio paths and identity, SCTs, Rekor signed entry timestamps and inclusion proofs, checkpoints, RFC 3161 timestamps, exact subjects, and GitHub workflow provenance from embedded versioned public roots.

The implementation is tested against every applicable case in the pinned official Sigstore conformance suite for this claimed profile, including negative proof cases. The real gateway fixture is also verified differentially with `gh attestation verify`, `sigstore-go`, the native `sigstore-rust` backend, and the RustCrypto/WASM backend.

Unsupported Sigstore profiles fail closed.

## Freshness

Host time is required because drand proves that evidence could not predate a round; it cannot prove the caller's current time. The default node-evidence policy is three minutes and can be tightened to one minute.

`expires_at` is the only refresh deadline. `serve` fetches a replacement 30–60 seconds before expiry, includes the public endpoint's ten-second shared-cache allowance, and retries in the background with jitter. It does not synchronously refresh after a connection or pin failure. If no valid replacement exists at expiry, new requests fail closed.

## Test suite

Run the native core, CLI, and binding tests:

```console
cargo test --locked --workspace --all-targets
```

The browser, Node, Go, conformance, and packaged-artifact commands are kept executable in [the CI workflow](.github/workflows/ci.yml), including their required build steps. GitHub CI runs:

- Rust format, Clippy, and native tests on Linux x86-64/ARM64, macOS x86-64/ARM64, and Windows x86-64;
- Go and C ABI tests;
- browser and Node package tests;
- Playwright with all browser networking blocked;
- official Sigstore conformance and differential verification;
- malformed-proof mutations and sanitized fuzz-target smoke tests.

The scheduled fuzz workflow exercises JSON, Sigstore, X.509, SNP, drand, WebAssembly, and C ABI boundaries.

## Evidence endpoints

- Production: `https://evidence.stogas.ai/bundles/latest.json`
- Staging: `https://evidence-staging.stogas.ai/bundles/latest.json`

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Copyright 2026 Stogas LLC. Licensed under Apache-2.0; see [LICENSE](LICENSE).
