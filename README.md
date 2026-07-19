# Stogas Verifier

Verify Stogas confidential gateways before trusting their keys or sending requests.

The verifier checks a public evidence bundle locally. It does not contact GitHub, Sigstore, AMD, drand, or Stogas during verification, and it does not write verifier state to disk.

## Choose an integration

| Need                                                                 | Use                       | Runs in                                                     |
| -------------------------------------------------------------------- | ------------------------- | ----------------------------------------------------------- |
| Use an existing OpenAI-compatible client with automatic verification | `stogas-verify serve`     | Linux, macOS, Windows                                       |
| Inspect a downloaded bundle or verify one in CI                      | `stogas-verify verify`    | Linux, macOS, Windows                                       |
| Keep a verified trust set inside an application                      | Stogas Verifier SDK       | Rust, JavaScript, browser, Worker, Node, Bun, Python, Go, C |
| Verify only GitHub/Sigstore provenance                               | `stogas-offline-sigstore` | Rust, JavaScript, browser, Worker, Node, Bun                |

## CLI

### Verified local endpoint

```console
stogas-verify serve
```

Point any OpenAI-compatible client at `http://127.0.0.1:8787/v1`. The proxy:

- keeps the evidence bundle current until its verified expiry;
- performs normal WebPKI and hostname verification;
- requires the certificate and public-key hashes from the same attested gateway;
- forwards `/v1/*` requests and streaming responses without installing a local CA.

`serve` is a native application. It is the right choice when the calling application cannot perform TLS pinning itself.

### Verify a file

```console
stogas-verify verify bundle.json
```

Use `-` to read from standard input. The command prints the verified release, trusted gateways, excluded stale gateways, and bundle expiry.

## SDK

Use an SDK when your application already owns bundle retrieval and connection handling.

```js
import { Verifier } from '@stogas/verifier';

const response = await fetch('https://evidence.stogas.ai/bundles/latest.json');
const verifier = new Verifier();
const result = verifier.verify_bundle(new Uint8Array(await response.arrayBuffer()));

console.log(result.bundle.nodes);
```

Browser code imports `@stogas/verifier/browser` and calls its default WebAssembly initializer once. Browser `fetch` does not expose the peer certificate, so a browser SDK can verify bundle evidence but cannot provide the CLI proxy's pre-request TLS pinning.

The client API has two forms:

- `verify_bundle(bytes)` for one verification;
- `new Verifier().verify_bundle(bytes)` when verifying successive bundles. The instance reuses already verified immutable release provenance in memory.

Both read the platform clock once. Neither fetches, schedules refreshes, persists state, or makes requests to the inference API.

## Packages

| Package                           | Purpose                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| `stogas-verifier`                 | Rust verification core                                          |
| `stogas-verify`                   | Native CLI and loopback proxy                                   |
| `@stogas/verifier`                | JavaScript and WebAssembly SDK                                  |
| `stogas-verifier` on PyPI         | Python 3.10+ native PyO3 extension                              |
| `github.com/StogasAI/verifier/go` | Go binding to the packaged native library                       |
| `stogas_verifier.h`               | Bounded C ABI for native integrations                           |
| `stogas-offline-sigstore`         | Generic Rust verifier for the supported GitHub/Sigstore profile |
| `@stogas/offline-sigstore`        | JavaScript/WebAssembly build of the Sigstore verifier           |

Python wheels use PyO3's stable `abi3-py310` ABI. Go uses cgo. The native packages cover Linux x86-64/ARM64, macOS x86-64/ARM64, and Windows x86-64.

## What is verified

A trusted result means that:

- GitHub built the attested IGVM and launch policy from the expected Stogas gateway repository and workflow;
- the independent Stogas release signature authorizes those same launch-policy bytes;
- each trusted gateway presents a valid AMD SEV-SNP report for an authorized launch measurement;
- the report binds that gateway's TLS, certificate-rotation, response-signing, and encryption keys;
- AMD revocation data, certificates, drand freshness, and the bundle itself remain valid through bundle expiry.

Cryptographically valid records that do not satisfy the selected freshness window are returned under `excluded_nodes`; they are never added to the trusted node set.

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
