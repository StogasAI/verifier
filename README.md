# Stogas Verifier

The Stogas SDK verifies confidential gateways before sending credentials or inference content.
One Rust core serves native clients and browser WebAssembly.

## Transport

| Mode         | Runtime                                | Connection                                                           |
| ------------ | -------------------------------------- | -------------------------------------------------------------------- |
| Attested TLS | Rust, Python, Go, C and the native CLI | Fresh hardware evidence in TLS 1.3 with mandatory X25519MLKEM768     |
| E2EE         | Native and Fetch runtimes              | Fresh attestation and reusable hybrid encryption over ordinary HTTPS |

Native clients default to TLS. Browser, Worker, Node, Bun and Deno Fetch integrations use E2EE.
Encrypted request and response records are binary. There is no combined mode or classical fallback
inside the attested profiles.

## Native SDK

```rust
use stogas::{SecurityMode, Transport, TransportOptions};

let mut transport = Transport::start(&TransportOptions {
    security: SecurityMode::Tls,
    max_connections: 4,
    ..TransportOptions::default()
})?;
// Use transport.base_url() with your OpenAI-compatible client; disable automatic retries.
transport.close();
```

The SDK provides a capability-protected loopback URL. The same engine runs through Python's
`Transport`, Go's `NewTransport`, and `stogas_transport_start` in the C ABI. Options select
the environment, `tls` or `e2ee`, a positive connection maximum (default four), and an optional
HTTPS origin override. Evidence roots and origins remain compiled into the package.

Connections open lazily under peer-capacity pressure. One transport can serve many requests.
Explicit close waits for bounded graceful cleanup; Rust Drop and language finalization only signal
shutdown. Inference is never automatically replayed after an ambiguous submission.

## CLI

```console
stogas-verify serve --security tls --max-connections 4
```

Pass the complete printed URL, including its random capability, to your client. The listener is
loopback-only and accepts Chat Completions and Responses. `--security e2ee` selects application
encryption. `--browser-origin https://app.example.com` permits one browser origin without changing
the selected transport. Use `serve --help` for all options.
Stop it with Ctrl+C, or SIGTERM on Unix, for bounded graceful cleanup.

`stogas-verify verify bundle.json --json` verifies a downloaded current bundle without network
access and reports its approved releases and catalogs. `--environment` selects compiled trust.

`stogas-verify proof --bundle bundle.json --boot boot-archive.json
--request request.json --response response.json` verifies a saved content receipt offline.
The default reads buffered JSON; `--stream` reads a complete SSE response. Detached verification
uses `--proof stogas.json` with the complete final metadata object and exact response bytes.
One signature authenticates the request, response and canonical metadata, excluding the receipt
itself. The supplied bundle appraises the logged boot; the receipt does not establish an execution time.

## Fetch SDK

Initialize the Wasm package once, then reuse `StogasTransport.create()` and its `openAIOptions()`
with the OpenAI JavaScript client. Close it with `await transport.close()` when done. Browser APIs
do not expose TLS verification hooks, so this adapter uses the verified E2EE protocol.
See the [JavaScript guide](https://stogas.ai/docs/javascript-typescript) for complete examples.

## Evidence and receipts

Initialization loads our current evidence from R2, with an independent AWS replica for recovery.
The networkless verifier checks root-authorized online keys, approved releases/catalogs, hardware
policy, build proofs, vendor collateral and CRLs. Each connection verifies its fresh challenge,
logged boot identity and bound session keys before releasing credentials or request content.

There is no SDK background polling. Explicit refresh and one bounded setup recovery reuse verified
objects. A lagging successful CDN response does not prevent trying the replica. Invalid signatures,
revocation and missing evidence retain distinct failure reasons. Verification does not fetch from
AMD, Intel, Rekor or GitHub and writes no trust state to disk.

Send `Stogas-Metadata: v1` to request final metadata. Its receipt signs the exact request and response
content and canonical metadata, excluding the receipt itself. Managed transports verify requested receipts against the
request's retained evidence. A stream can release content before verification finishes, but cannot
report normal completion without the final verified receipt. Receipt recovery never repeats inference.

The Rust `stogas_verifier::evidence::Verifier` and the Wasm/C evidence APIs also accept evidence bytes
for offline verification. Go uses `NewEvidence`, `Refresh` and the retained snapshot; C uses the
`stogas_evidence_*` functions. `VerifyReceipt` / `stogas_evidence_verify_receipt` take the complete final `stogas` bag, including its receipt,
and SHA-256 hashes computed from the exact signed content.
An archived boot record and its log proof remain unchanged when current
collateral or approvals are refreshed.

For saved receipts, use Go's `VerifyReceiptArchive`, C's
`stogas_evidence_verify_receipt_archive`, or Python's `verify_boot_archive` followed by
`verify_receipt`. Supply the complete `stogas` bag, boot archive and its referenced evidence bundle. These methods
appraise the boot at its authenticated log time, so routine collateral expiry does not erase
history. They do not restore current serving permission or establish when inference occurred.

Applications embedding only offline verification can build `stogas-verifier-ffi` with
`--no-default-features`. This omits the HTTP client, connection pools and managed transport ABI.
The Go binding's matching `stogas_offline` build tag omits `Transport`; normal SDK builds keep it.

## Packages

| Package                           | Purpose                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| `stogas`                          | Complete Rust SDK                                               |
| `stogas-verify`                   | Native CLI and loopback proxy                                   |
| `@stogas/verifier`                | JavaScript and WebAssembly SDK                                  |
| `stogas-verifier` on PyPI         | Python 3.10+ SDK through a native PyO3 extension                |
| `github.com/StogasAI/verifier/go` | Go SDK through the packaged native library                      |
| [Java](bindings/java/)           | Native transport for Java 17+, Kotlin, Scala and Clojure        |
| [.NET](bindings/dotnet/)         | Native transport for C# and F#                                  |
| [Ruby](bindings/ruby/)           | Native transport with explicit and block-based cleanup         |
| [Swift](bindings/swift/)         | Native transport for macOS and Linux                            |
| `stogas_verifier.h`               | Complete bounded C ABI for native integrations                  |
| `stogas-offline-sigstore`         | Generic Rust verifier for the supported GitHub/Sigstore profile |
| `@stogas/offline-sigstore`        | JavaScript/WebAssembly build of the Sigstore verifier           |

Python wheels use PyO3's stable `abi3-py310` ABI. Go uses cgo. The native packages cover Linux x86-64/ARM64, macOS x86-64/ARM64, and Windows x86-64.

Use your language's OpenAI client with the verifier transport. OpenAI request types remain
in that client; the Rust SDK does not bundle or re-export `async-openai`. The
[examples](examples/) cover maintained clients and standard HTTP, streaming, cancellation,
and cleanup. Their tests also check that client retries and truncated streams do not hide
an incomplete request. See the [language guides](https://stogas.ai/docs/sdk-overview).

Supervised CLI children can pass `--exit-on-stdin-close` and keep stdin piped.
Closing that pipe, including after the parent exits, requests graceful cleanup.
Without the option, closing stdin does not stop the CLI.

Other runtimes can use the C ABI or the CLI's local URL. The language guides include complete
native bridges or supervised CLI examples. See the [C and C++ guide](https://stogas.ai/docs/c-cpp)
for the ABI and memory-ownership contract.

## Sigstore support

`stogas-offline-sigstore` supports the GitHub `actions/attest` v0.3 DSSE/in-toto SLSA profile and the strict Stogas-keyed DSSE/Rekor v1 profile used by hardware policies. Unsupported signing profiles fail closed.

CI checks the supported profile against the applicable official Sigstore conformance cases, `gh attestation verify`, `sigstore-go`, `sigstore-rust`, and the RustCrypto/WebAssembly backend. Browser tests run with every network request blocked.

## Development

Run the Rust workspace tests:

```console
cargo test --locked --workspace --all-targets
```

The [CI workflow](.github/workflows/ci.yml) also tests browser WebAssembly, Node, Python artifacts, Go/C bindings, fresh TLS attestation, official Sigstore cases, malformed evidence, and all supported native platforms. [Continuous fuzzing](.github/workflows/fuzz.yml) covers the parsers and native trust boundaries.

Security issues should be reported according to [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
