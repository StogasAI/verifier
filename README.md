# Stogas Verifier

Offline verification for the Stogas confidential-gateway evidence bundle.

One deterministic Rust engine powers the native CLI, Rust, browser WebAssembly, Node, Bun,
Python, Go, and C interfaces. Each adapter captures the platform clock once and delegates every
trust decision to the same core. Verification performs no network requests and writes no
persistent state.

## Packages

- `stogas-offline-sigstore`: networkless verification of the supported GitHub/Sigstore in-toto
  profile.
- `stogas-verifier`: complete verification of `stogas.confidential-bundle.v1`.
- `stogas-verify`: offline verification and an optional loopback OpenAI-compatible proxy.
- `@stogas/offline-sigstore`: generic Sigstore WASM for browsers, Workers, Node, and Bun.
- `@stogas/verifier`: complete Stogas bundle WASM for browsers, Workers, Node, and Bun.
- Python `stogas-verifier`: native PyO3 `abi3-py310` wheels for CPython 3.10 and newer.
- `github.com/StogasAI/verifier/go`: a thin cgo adapter around the Rust library.
- `stogas_verifier.h`: a bounded C ABI for native and enterprise integrations.

The standalone Sigstore package excludes SNP, drand, and Stogas policy. AMD/SNP verification
remains an implementation detail of the complete verifier rather than a separately branded quote
library.

Stogas does not require a separate inference SDK. Existing OpenAI-compatible clients can use the
Stogas API by changing their base URL. Applications that want verification and TLS pinning without
embedding a language binding can use `stogas-verify serve`.

## Verification Model

The bundle is a collection of independently authenticated evidence:

- every release must have an official GitHub/Sigstore attestation and a Stogas release signature
  over the same launch policy and IGVM digest;
- every node must have a valid AMD SEV-SNP certificate chain, revocation material, report
  signature, approved launch measurement, report-data binding, certificate stack, and drand proof;
- the verifier uses its captured wall clock to enforce bundle, certificate, collateral, Sigstore,
  and node-evidence deadlines.

The envelope SHA-256 detects accidental corruption and provides a stable content identifier. It is
not an authority: changing it cannot make invalid release or node evidence pass. A separate fleet
signing key is therefore unnecessary. Node Ed25519 keys are generated inside each guest and bound
by its SNP report data; they authenticate node-produced application evidence after admission, not
the bundle itself.

Malformed evidence, unsupported algorithms, invalid releases, or invalid node proofs reject the
bundle. A cryptographically valid node outside the caller's freshness policy is returned under
`excluded_nodes` and never enters the current trust set.

## CLI

```console
stogas-verify verify bundle.json
stogas-verify verify - --json
stogas-verify serve
```

`verify` reads a file or standard input and never accesses the network. `serve` fetches and verifies
a bundle before listening on loopback, refreshes against the earliest trust deadline with jitter,
and stops starting requests when no fresh trust remains.

The proxy accepts `/v1/*` and preserves OpenAI-compatible requests, authorization headers,
responses, and streaming bytes. The actual upstream connection must pass normal WebPKI and
hostname verification. Its leaf-certificate hash and DER SubjectPublicKeyInfo SHA-256 must then
match the same verified node. Either certificate in that node's attested two-slot rotation stack
may be presented. The proxy installs no local CA and does not log API keys, request bodies, or model
output.

Standard evidence endpoints:

- production: `https://evidence.stogas.ai/bundles/latest.json`
- staging: `https://evidence-staging.stogas.ai/bundles/latest.json`

The endpoints are public, read-only R2 custom domains with wildcard read-only CORS. Independent
browser applications can therefore fetch and verify evidence without credentials.

## SDK Boundary

Rust, WASM, Python, Go, and C expose a reusable `Verifier` and a stateless convenience call. The
reusable verifier caches only immutable release verification in memory. Normal calls capture the
host clock once; explicit `*_at` calls accept an exact time for deterministic audits and tests.

SDKs do not fetch bundles, schedule refreshes, persist state, proxy requests, or choose a network
route. Those concerns remain with the host application. `stogas-verify serve` provides the
maintained background-fetch and connection-pinning implementation.

The WASM package also exposes the release, AMD-collateral, and heartbeat admission boundaries used
by the Stogas Control service. They use the same Rust policy and are not alternative client
verification paths.

## Sigstore Profile

`stogas-offline-sigstore` verifies the production GitHub `actions/attest` v0.3 DSSE/in-toto profile
used by gateway releases. It validates exact artifact subjects, Fulcio certificate paths and GitHub
identity, SCTs, Rekor signed-entry timestamps and inclusion proofs, signed checkpoints, RFC 3161
timestamps, and SLSA provenance.

The package embeds a versioned public Sigstore trusted-root snapshot. It never contacts TUF,
Fulcio, Rekor, GitHub, a registry, or an OIDC service. Unsupported bundle versions, roots, signing
styles, or required fields are rejected.

The browser implementation uses `rustls-webpki` path construction with narrow RustCrypto signature
adapters. Its dependency graph excludes OpenSSL, `ring`, and AWS-LC so the same policy compiles to
`wasm32-unknown-unknown` without native C dependencies.

## Freshness And Caching

Host wall time is required because drand proves that evidence could not predate a round; it does not
prove that the caller's current clock is recent. The verifier checks bundle creation and expiry,
future timestamps, certificate and collateral validity, and authenticated Sigstore time against one
captured wall-clock value.

Control accepts a node proof only when its verified Quicknet round was at most two minutes old at
admission and did not regress. Clients admit a node for at most three minutes from that verified
round and may choose a stricter one-to-three-minute policy. The node deadline is capped by bundle
expiry; bundle lifetime is never added to the drand allowance.

`expires_at` is the hard bundle deadline. The mutable latest object uses
`max-age=0, s-maxage=10, must-revalidate` so Cloudflare may share it for at most ten seconds without
instructing clients to extend trust. Source sequence objects remain available for 31 days. Clients
and independent mirrors may retain their already fetched copies for longer.

Verification returns both bundle expiry and the earliest node-trust expiry. `serve` refreshes at
the earlier deadline with randomized lead time and retry delay, which prevents synchronized client
fetches.

## Language Support

- Rust, browser/Web Worker, Node, Bun, Python, and Go have maintained language APIs.
- Linux x86-64/ARM64, macOS x86-64/ARM64, and Windows x86-64 receive native CLI and C artifacts.
- Java 22+ can bind the C ABI through the Foreign Function and Memory API.
- .NET can bind the same ABI with P/Invoke.
- Swift and Kotlin do not currently have maintained Stogas packages; the core remains compatible
  with generated UniFFI bindings without adding a second verification implementation.

The C boundary accepts bounded byte buffers and returns bounded JSON. It does not expose
cryptographic primitives.

## Historical Evidence

Clients never search Rekor or an archive to accept a current node. Each current bundle is
self-contained. Rekor records the GitHub release provenance for which it was designed; it is not a
fleet database.

Stogas retains each admitted node's quote, report-data preimage, bound keys, collateral, drand round,
and linked immutable release provenance. Public sequence objects provide a 31-day audit and mirror
window. These records support historical verification without placing an external transparency log
in the runtime trust path.

See [SECURITY.md](SECURITY.md) to report vulnerabilities.

## License

Copyright 2026 Stogas LLC. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE).
