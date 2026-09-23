# Stogas for Swift

This Swift 6.2 package links the Rust verifier through its C ABI. Native artifacts support macOS 13 or later and Linux on x86-64 and ARM64. It does not include iOS or Windows artifacts.

```swift
import StogasVerifier

let transport = try Transport()
defer { transport.close() }
let baseURL = transport.baseURL
// Configure your HTTP client with baseURL and automatic retries and proxies disabled.
```

Keep one transport for the application's lifetime. Startup and `refresh()` perform blocking setup work; run them off your UI event loop. The default is native attested TLS. `TransportOptions(security: "e2ee")` selects binary E2EE. Other options are `maxConnections` and `baseURL`; the latter changes the inference origin without changing trusted evidence authorities. Staging requires a separately built staging library.

Finish your HTTP clients before `close()`. Cleanup waits up to five seconds, is safe to repeat and also runs when the transport is released. Concurrent refresh and close are serialized. Native failures preserve their reason in `VerificationError.native(code:message:)`.

The package includes no OpenAI request schemas. Use Foundation or your chosen API client; the Swift HTTP example checks HTTP errors, cancellation and authenticated stream completion.
