# Stogas transport for .NET

Use the verified transport with your preferred OpenAI or HTTP client. The package uses the same Rust verifier as the Stogas CLI; it does not implement a second inference API.

```csharp
using Stogas.Verifier;

using var transport = new Transport();
using var http = new HttpClient(new SocketsHttpHandler
{
    UseProxy = false,
    AllowAutoRedirect = false
});
// Set your client's base URL to transport.BaseUrl and disable its retries.
```

`TransportOptions` selects `Security` (`tls` or `e2ee`) and `MaxConnections` (default 4). `Environment` defaults to `prod`; staging requires a staging native build. Initialization verifies evidence before returning. `Refresh()` refreshes evidence without replaying requests. `VerificationException.Code` is the structured native error code.

Dispose the transport after all clients using it finish. Disposal is safe to repeat and allows up to five seconds for graceful cleanup. A failed or interrupted inference must not be retried automatically.

The native package supports 64-bit Linux, macOS and Windows targets. Mobile targets are not included.
