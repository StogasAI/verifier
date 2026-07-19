# `@stogas/offline-sigstore`

Small, networkless WebAssembly verifier for the standard GitHub/Sigstore v0.3 DSSE and in-toto
profile supported by Stogas. It verifies embedded Fulcio, SCT, Rekor, RFC 3161, subject, identity,
and GitHub Actions provenance material without fetching TUF or calling Sigstore services.

Use `@stogas/verifier` when verifying a complete Stogas confidential-gateway bundle. This package
contains no Stogas, AMD SNP, certificate-pinning, or drand policy.

```js
import { verify_github_attestation } from '@stogas/offline-sigstore';

const verified = verify_github_attestation(
	attestationBytes,
	JSON.stringify(subjects),
	JSON.stringify(policy)
);
```

The default Node/Bun export initializes WebAssembly synchronously. Browser consumers initialize
the `/browser` module once with its default initializer; compatible Workers use `/worker`.
