# Stogas SDK

Verify Stogas confidential gateways before sending credentials or inference content.
One Rust core powers native clients, WebAssembly and offline verification.

[Documentation](https://stogas.ai/docs/sdk-overview) · [Examples](examples/) · [Security](SECURITY.md)

## What it does

- Verifies hardware attestation, approved builds and session keys.
- Connects through attested TLS or end-to-end encryption over HTTPS.
- Verifies signed request receipts, including the final Stogas metadata.
- Checks downloaded evidence and saved receipts offline.

Use the verifier transport with your language's OpenAI-compatible client or HTTP library.
It handles verification and transport; your client handles request types and API methods.

## Get started

Choose a [language guide](https://stogas.ai/docs/sdk-overview) or a runnable [example](examples/).
Native bindings include Rust, Python, Go, C, Java, .NET, Ruby and Swift. JavaScript uses
WebAssembly with Fetch-compatible runtimes.

The CLI can also provide a local endpoint for an existing client:

```console
stogas serve --security tls
```

Use the complete URL printed by the command as your client's base URL. Keep its capability
private and disable automatic inference retries. Use `--security e2ee` for encrypted transport
over HTTPS, and stop the process with Ctrl+C.

For offline verification:

```console
stogas verify evidence.json --json
stogas proof --help
```

## Customer encryption

Generate a private organization key and encrypt a plugin configuration or provider credential locally:

```console
stogas encryption-key --output org.key
stogas encrypt --key-file org.key --organization ORGANIZATION_ID --purpose plugins --input plugins.json --output encrypted.json
```

Key generation prints only the public identifier. Back up the private key file; we cannot recover it.
The `plugins` input is the inner plugin object. Provider purposes are `byok/openai`, `byok/anthropic`
and `byok/chutes`; credential files contain the exact secret without a trailing newline.
Follow the [encryption guide](https://stogas.ai/docs/cli#encrypt-credentials-and-plugins) to register
ciphertext and supply roots by their registered labels in `encryption_keys` in the request body. The gateway accepts ordinary HTTPS;
we recommend attested TLS or E2EE to keep the key private from TLS intermediaries.

## Verification

The verifier checks signed approvals, hardware policy, build provenance and vendor collateral.
Live connections also require fresh attestation bound to their session keys. Stogas signatures
use ML-DSA-65; external hardware and transparency services retain their own signature algorithms.

A hardware policy can assign a chip to several configuration groups during a transition. A report
must satisfy every requirement of one matching group; requirements are never combined across groups.
Chip IDs are unique and sorted within each group. Groups are unique and sorted by their canonical
JSON. Removing an alternative withdraws that configuration when the current policy is checked.

Registration authorities can retain `VerifiedRegistration::registered_facts()` for policy previews
through `Snapshot::appraise_registered_boot`. This method trusts previously verified stored facts;
it does not authenticate supplied evidence or establish a live session. Use logged-boot verification
for evidence supplied by a gateway.

Streaming content can arrive before final verification. Applications must wait for verified
completion before treating a response as complete.

This project is pre-1.0. APIs and package interfaces may change.

## Contributing

```console
cargo test --locked --workspace --all-targets
```

[CI](.github/workflows/ci.yml) covers the core, transports and language bindings.
[Fuzzing](.github/workflows/fuzz.yml) exercises parsers and verification boundaries.
Report vulnerabilities through the [security policy](SECURITY.md).

## License

[Apache-2.0](LICENSE).
