# Stogas Verifier

Verify Stogas confidential gateways before trusting their keys or sending requests.

The verifier checks a public evidence bundle locally. It does not contact GitHub, Sigstore, AMD, drand, or Stogas during verification, and it does not write verifier state to disk.

## Choose an integration

| Need                                                                 | Use                       | Runs in                                                     |
| -------------------------------------------------------------------- | ------------------------- | ----------------------------------------------------------- |
| Use an existing OpenAI-compatible client with automatic verification | Stogas SDK `Transport`    | Native SDKs, browser, Worker, Node, Bun, Deno               |
| Inspect a downloaded bundle or verify one in CI                      | `stogas-verify verify`    | Linux, macOS, Windows                                       |
| Keep a verified trust set inside an application                      | Stogas Verifier SDK       | Rust, JavaScript, browser, Worker, Node, Bun, Python, Go, C |
| Verify only GitHub/Sigstore provenance                               | `stogas-offline-sigstore` | Rust, JavaScript, browser, Worker, Node, Bun                |

## CLI

### Verified local endpoint

```console
stogas-verify serve
```

Point any OpenAI-compatible client at `http://127.0.0.1:8787/v1`. The proxy:

- randomly polls one independent evidence origin every minute by default, falls back to the other
  after fetch, verification, or sequence regression failure, and avoids reverifying identical bytes;
- supports attested TLS, E2EE, or both on the normal inference endpoints;
- defaults to WebPKI plus certificate and public-key pinning in native mode;
- forwards `/v1/*` requests and streaming responses without installing a local CA.

The official origins are `https://evidence.stogas.ai/bundles/latest.json` on Cloudflare/R2 and
`https://evidence2.stogas.ai/bundles/latest.json` on AWS CloudFront/S3.

`serve` is a native application. It is the right choice when the calling application cannot perform TLS pinning itself.

Browser applications can opt in one exact origin:

```console
stogas-verify serve --browser-origin https://app.example.com
```

The CLI prints a capability-protected base URL for that browser session. It handles CORS and local-network preflights without allowing other origins or forwarding local access headers upstream, and defaults browser-origin traffic to E2EE.

Use `--security tls|e2ee|both` to select the transport policy. Use `--bundle-refresh-seconds` to select 1 to 840 seconds; zero is not accepted. The proxy also fetches before the hard bundle expiry, so a long interval cannot skip the final replacement window.

### Verify a file

```console
stogas-verify verify bundle.json
```

Use `-` to read from standard input. The command prints the verified release, trusted gateways, excluded stale gateways, and bundle expiry.

## SDK

Each language installs one Stogas SDK. `Transport` owns snapshot refresh, attested TLS, E2EE,
streaming, and fail-closed expiry; `Verifier` performs explicit networkless snapshot and receipt
checks. Native transports run the Rust connection engine inside the application process. Fetch
runtimes use the same core through WebAssembly and E2EE.

Use `Verifier` when the application owns retrieval and needs the verified trust data directly:

```js
import { Verifier } from '@stogas/verifier';

const response = await fetch('https://evidence.stogas.ai/bundles/latest.json');
const verifier = new Verifier();
const result = verifier.verify_bundle(new Uint8Array(await response.arrayBuffer()));

console.log(result.bundle.nodes);
```

Browser code imports `@stogas/verifier/browser` and calls its default WebAssembly initializer once. Its `StogasTransport` verifies bundles, encrypts requests to every accepted node, and supplies a custom `fetch` for the OpenAI JavaScript client. Browser `fetch` does not expose the peer certificate, so direct browser mode provides E2EE rather than attested TLS.

`StogasTransport.bundleURLs` exposes the configured evidence origins.
`StogasTransport.bundleSnapshot` reports the origin used by the latest successful refresh, when the
accepted bytes were verified, and the measured local cryptographic verification time. Byte-identical
refreshes reuse the earlier verified result and its measurement.

The client API has two forms:

- `verify_bundle(bytes)` for one verification;
- `new Verifier().verify_bundle(bytes)` when verifying successive bundles. The instance reuses already verified immutable release provenance in memory.

Both verifier forms read the platform clock once. Neither fetches, schedules refreshes, persists state, or makes requests to the inference API.

### Verify a response receipt

The same verifier checks compact response receipts against the active bundle:

```js
const receipt = verifier.verify_response_proof(proofBytes, requestBytes, responseBytes);
```

Use `verify_historical_response_proof` with an immutable node-ledger record when the signing gateway is no longer in the active bundle.

The receipt requires the exact plaintext request and response bytes. For streaming, omit the final `stogas.proof` event from the response bytes. When the exchange was encrypted, preserve the locally computed `X-Stogas-E2EE-Transcript-SHA256` response header and supply it during verification.

`StogasTransport.verifyResponseProof(...)` performs the same check against the transport's
already accepted bundle, avoiding a second bundle fetch and verification in managed clients.

## Packages

| Package                           | Purpose                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| `stogas`                          | Complete Rust SDK                                               |
| `stogas-verify`                   | Native CLI and loopback proxy                                   |
| `@stogas/verifier`                | JavaScript and WebAssembly SDK                                  |
| `stogas-verifier` on PyPI         | Python 3.10+ SDK through a native PyO3 extension                |
| `github.com/StogasAI/verifier/go` | Go SDK through the packaged native library                      |
| `stogas_verifier.h`               | Complete bounded C ABI for native integrations                  |
| `stogas-offline-sigstore`         | Generic Rust verifier for the supported GitHub/Sigstore profile |
| `@stogas/offline-sigstore`        | JavaScript/WebAssembly build of the Sigstore verifier           |

Python wheels use PyO3's stable `abi3-py310` ABI. Go uses cgo. The native packages cover Linux x86-64/ARM64, macOS x86-64/ARM64, and Windows x86-64.

Java 22+ and other JVM languages can use the Foreign Function & Memory API, .NET can use P/Invoke, Swift and Objective-C have native C interoperability, and Kotlin/Native can use `cinterop`. These are self-managed C ABI integrations rather than separate Stogas SDK implementations. See the [C and C++ guide](https://stogas.ai/docs/c-cpp) for the ABI and memory-ownership contract.

## What is verified

A trusted result means that:

- GitHub built the attested IGVM and launch policy from the expected Stogas gateway repository and workflow;
- the independent Stogas release signature authorizes those same launch-policy bytes;
- each trusted gateway presents a valid AMD SEV-SNP report for an authorized launch measurement;
- the report binds that gateway's TLS, certificate-rotation, response-signing, and encryption keys;
- the bundle was created within three minutes, remains unexpired, and has a validity interval of no more than 15 minutes;
- each trusted gateway's drand evidence was no more than two minutes old when the bundle was created.

Older valid records are returned under `excluded_nodes`; they are never added to the trusted node set.

## Sigstore support

`stogas-offline-sigstore` supports the GitHub `actions/attest` v0.3 DSSE/in-toto SLSA profile used by gateway releases. Unsupported signing profiles fail closed.

CI checks the supported profile against the applicable official Sigstore conformance cases, `gh attestation verify`, `sigstore-go`, `sigstore-rust`, and the RustCrypto/WebAssembly backend. Browser tests run with every network request blocked.

## Development

Run the Rust workspace tests:

```console
cargo test --locked --workspace --all-targets
```

The [CI workflow](.github/workflows/ci.yml) also tests browser WebAssembly, Node, Python artifacts, Go/C bindings, TLS pinning, official Sigstore cases, malformed evidence, and all supported native platforms. [Continuous fuzzing](.github/workflows/fuzz.yml) covers the parsers and native trust boundaries.

Security issues should be reported according to [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
