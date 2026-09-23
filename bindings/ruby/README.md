# Stogas transport for Ruby

```ruby
require 'stogas_verifier'
require 'openai'

Stogas::Transport.open do |transport|
  client = OpenAI::Client.new(
    api_key: ENV.fetch('STOGAS_API_KEY'),
    base_url: transport.base_url,
    max_retries: 0
  )
  # Send typed requests with the OpenAI client.
end
```

The package wraps the Rust verifier and includes its native library. It performs no inference retries and has no OpenAI dependency. Use `security: 'e2ee'` for application encryption; the default `tls` uses native attested TLS. `max_connections:` defaults to four. Staging needs a staging native build and `environment: 'staging'`.

`refresh` updates verification evidence. `Stogas::VerificationError#code` preserves the native error code. The block closes the transport even when application code raises. Without a block, call `close` after all HTTP clients finish; cleanup allows up to five seconds. Calling `close` again is safe.

Bypass proxies for the returned loopback URL. With Ruby Net::HTTP, set `ignore_eof = false` so truncated responses cannot look complete. Do not automatically retry interrupted inference.
