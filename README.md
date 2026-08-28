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

- polls one randomly selected evidence origin on a five-minute target with ±10% jitter by default, falls back to the other
  after network, HTTP, local-verification, or snapshot-order failure, and avoids reverifying
  identical bytes;
- supports attested TLS, E2EE, or both on the normal inference endpoints;
- requires TLS 1.3 with X25519MLKEM768, WebPKI, and certificate and public-key pinning in native `tls` and `both` modes;
- sends E2EE over ordinary WebPKI HTTPS when hybrid TLS is unavailable;
- carries pass-through provider credential headers only inside the E2EE request;
- verifies every requested buffered or streaming receipt before reporting normal completion;
- keeps polling every four to eight seconds and returns HTTP 503 when a verified bundle has no
  trusted gateways;
- forwards `/v1/*` requests and streaming responses without installing a local CA.

The official origins are `https://evidence.stogas.ai/bundles/latest.json` on Cloudflare/R2 and
`https://evidence2.stogas.ai/bundles/latest.json` on AWS CloudFront/S3.

`serve` is a native application. It is the right choice when the calling application cannot perform TLS pinning itself.

Browser applications can opt in one exact origin:

```console
stogas-verify serve --browser-origin https://app.example.com
```

The CLI prints a capability-protected base URL for that browser session. It handles CORS and local-network preflights without allowing other origins or forwarding local access headers upstream, and defaults browser-origin traffic to E2EE.

Use `--security tls|e2ee|both` to select the transport policy. Bundle refresh uses a five-minute target by default; every configured target receives ±10% jitter. `--bundle-refresh-seconds` accepts any positive whole-second target. The proxy also fetches before the hard bundle expiry, so a long interval cannot skip the final replacement window. A valid empty trust set is an explicit unavailable state, not a verification failure. When a non-empty bundle is active, both official origins must return verified empty candidates before the proxy replaces it. This availability safeguard does not apply to a caller-selected single origin. Once active, an empty trust set blocks inference and starts the faster recovery polling above.

### Verify a file

```console
stogas-verify verify bundle.json
```

Use `-` to read from standard input. The command prints the verified release, trusted gateways, excluded stale gateways, and bundle expiry.

Each bundle has one hardware policy document with a Stogas Ed25519 DSSE signature and Rekor v1 proof. Each policy group lists the exact processor IDs that share its expected CPUID, AMD SEV-SNP minimum TCB, required report-v5 mitigation bits, and required platform state. It has no launch-policy field or pointer. The verifier derives the AMD product from signed report and VCEK fields; it does not accept a hardware label. The proof shows that Stogas signed and published the complete document. It does not prove that the policy matches every customer's risk decision. The schema name versions the format; the document has no ordering counter.

To own that decision, copy `body.hardware_policy.policy` from a bundle, review or tighten its requirements, and pass the bare policy file. The local file must keep every signed `chip_id`:

```console
stogas-verify verify bundle.json --policy hardware-policies.json
stogas-verify serve --policy hardware-policies.json
```

The local file does not need a Stogas signature. Its file distribution is the caller's trust boundary. The verifier still checks the bundled policy signature and every fixed quote, certificate, report binding, release, encoding, and freshness rule. A stricter local policy can make the complete fleet unavailable until its hardware is updated.

The shipped policy accepts one reviewed Milan B1 floor: bootloader 4, SNP 29, microcode 222,
mitigation bits 0, 1, and 3, ECC, completed alias checking, and either SMT state. It does not claim
mitigation bits 2 or 4. A customer that requires either bit can supply a stricter local policy,
which rejects the current fleet. AMD documents those additional mitigations in
[AMD-SB-3016](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3016.html) and
[AMD-SB-3034](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3034.html).
Passing attestation values does not replace required host or guest lifecycle work.

## SDK

Each language installs one Stogas SDK. `Transport` owns snapshot refresh, attested TLS, E2EE,
streaming, and fail-closed expiry; `Verifier` performs explicit networkless snapshot and receipt
checks. Native transports run the Rust connection engine inside the application process. Fetch
runtimes use the same core through WebAssembly and E2EE.

Rust, Python, Go, C, and the CLI use one capability-protected Rust loopback handler. The OpenAI
client serializes its normal request first, then that handler hashes and forwards the exact body
bytes it received. No language binding re-encodes the request or calculates its own proof hash.
Browser, Worker, Node, Bun, and Deno use the same Rust proof filter through WebAssembly around the
Fetch API.

Use `Verifier` when the application owns retrieval and needs the verified trust data directly:

```js
import { Verifier } from '@stogas/verifier';

const response = await fetch('https://evidence.stogas.ai/bundles/latest.json');
const verifier = new Verifier();
const result = verifier.verify_bundle(new Uint8Array(await response.arrayBuffer()));

console.log(result.bundle.nodes);
```

Use `verify_bundle_with_policy(bundleBytes, policyBytes)` to replace the mutable hardware requirements. Managed SDK transports accept the same bare policy as `hardwarePolicy` in JavaScript, `hardware_policy` in Rust and Python, and `HardwarePolicy` in Go. `result.bundle.hardware_policy` reports the processor IDs, policy count, hash, source, Stogas key ID, and verified Rekor time when the bundled default was used.

`result.bundle.catalogs` contains up to two verified catalog approvals. Each approval requires one
GitHub Actions attestation over the runtime and public hashes and one separate Stogas-signed
manifest from an independent build with the same hashes. The node signs its active catalog in
heartbeats and signs the catalog used for each response receipt; catalog identity is not report data.

Browser code imports `@stogas/verifier/browser` and calls its default WebAssembly initializer once. Its `StogasTransport` verifies bundles, encrypts requests to every accepted node, and supplies a custom `fetch` for the OpenAI JavaScript client. Browser `fetch` does not expose the peer certificate, so direct browser mode provides E2EE rather than attested TLS.

`StogasTransport.bundleURLs` exposes the configured evidence origins.
`StogasTransport.bundleSnapshot` reports the origin used by the latest successful refresh, when the
accepted bytes were verified, and the measured local cryptographic verification time. Byte-identical
refreshes reuse the earlier verified result and its measurement.

When a verified bundle has no trusted nodes, the snapshot status is `unavailable`. The transport
remains active, polls every four to eight seconds, and fails protected requests locally until a
newer verified bundle provides a trusted node.

The client API has two forms:

- `verify_bundle(bytes)` for one verification;
- `verify_bundle_with_policy(bytes, policy)` for verification with caller-owned AMD appraisal rules;
- `new Verifier().verify_bundle(bytes)` when verifying successive bundles. The instance reuses complete, content-hashed release and catalog approvals in memory.

Both verifier forms read the platform clock once. Neither fetches, schedules refreshes, persists state, or makes requests to the inference API.
The published artifact has one fixed provenance policy and accepts only GitHub/Sigstore evidence.

### Verify a response receipt

Send `Stogas-Receipt: v1` with the inference request. A buffered response adds a final top-level
`stogas` object. A stream returns the same compact JSON in one `: stogas {...}` SSE comment before
`[DONE]`, `response.completed`, or `response.incomplete`.

Managed `Transport` integrations verify this receipt automatically. They capture the verified
bundle and request bytes before dispatch. Buffered JSON is released after full verification. A
stream can release ordinary content as it arrives, but it withholds the terminal event delimiter
until the receipt, exact stream hash, node, catalog, and E2EE transcript have verified. A failed or
truncated stream therefore never reports normal completion.

The same verifier checks the decoded signed result against the active bundle:

```js
const receipt = verifier.verify_response_proof(requestBytes, responseBytes);
```

Use `verify_historical_response_proof` with the historical node evidence and catalog approval when the
signing node is no longer in the active bundle.

The receipt requires the exact plaintext request and response bytes. Active-bundle verification
also requires its exact node and catalog to be in the verified bundle. The signed result includes the
gateway-recorded request creation time and node ID, catalog identity and ordered selection IDs,
settled pricing, timing, hashes, and signature. For streaming, hash every exact SSE byte except the Stogas comment. Include
the terminal frame. When the exchange was encrypted, preserve the locally computed
`X-Stogas-E2EE-Transcript-SHA256` response header and supply it during verification.

Browser clients can verify a stream without retaining one response buffer:

```js
const stream = verifier.start_response_proof(requestBytes);
stream.write(frameBytes); // Call for each non-Stogas frame, including the terminal frame.
const receipt = stream.finish(proofBytes, e2eeTranscriptSHA256);
```

The one-shot body API has a 128 MiB limit. The stream API keeps only a running hash. The CLI also
hashes request and response files incrementally.

`StogasTransport.verifyResponseProof(...)` remains available for caller-owned retrieval or saved
responses. It checks against the transport's already accepted bundle without a second bundle fetch.

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

- GitHub built and attested the IGVM and complete release manifest from the expected Stogas gateway repository and workflow;
- the separate Stogas counterbuild approval authorizes that exact manifest, including the IGVM hash and launch values, after a matching rebuild;
- the hardware document has a valid Stogas Ed25519 DSSE signature and Rekor v1 inclusion proof;
- each processor assignment selects exactly one compatible launch rule in that release;
- each trusted gateway presents a valid AMD SEV-SNP report for an authorized launch measurement;
- the report CPUID, AMD product, VCEK structure, generation-specific hardware identifier, complete TCB, and pinned product root agree; unknown processor definitions fail closed;
- the stapled product CRL is issued and signed by that pinned ARK and does not revoke the ASK;
- the exact signed report bytes and signature encoding are valid, including all reserved bytes;
- report version 5 current, reported, committed, and launch TCB values, launch and current mitigation vectors, and platform state satisfy the applied hardware policy;
- the report binds that gateway's TLS, certificate-rotation, response-signing, and encryption keys;
- the unsigned bundle envelope's SHA-256 matches its canonical body, while every trust claim verifies to its embedded root;
- the bundle was created no more than three minutes before or one minute after local verification, remains unexpired, and has a positive validity interval of no more than 15 minutes;
- every trusted gateway certificate and required AMD validity deadline covers that complete interval;
- each trusted gateway's drand evidence was no more than two minutes old when the bundle was created.

Older valid records are returned under `excluded_nodes`; they are never added to the trusted node set.

## Sigstore support

`stogas-offline-sigstore` supports the GitHub `actions/attest` v0.3 DSSE/in-toto SLSA profile and the strict Stogas-keyed DSSE/Rekor v1 profile used by hardware policies. Unsupported signing profiles fail closed.

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
