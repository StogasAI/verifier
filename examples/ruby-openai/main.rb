# frozen_string_literal: true
require "openai"
require "stogas_verifier"

def stogas_client(base_url, api_key, http)
  OpenAI::Client.new(
    base_url: base_url,
    api_key: api_key,
    max_retries: 0,
    timeout: 45 * 60,
    http_client: http
  )
end

def local_http
  OpenAI::NetHTTPClient.new do |connection|
    connection.ignore_eof = false
    connection.proxy_from_env = false
    connection.proxy_address = nil
  end
end

if $PROGRAM_NAME == __FILE__
  # An explicit URL can also use a separately managed verifier CLI.
  transport = Stogas::Transport.new unless ENV.key?("STOGAS_BASE_URL")
  http = local_http
  stream = nil
  begin
    client = stogas_client(ENV.fetch("STOGAS_BASE_URL") { transport.base_url }, ENV.fetch("STOGAS_API_KEY"), http)
    stream = client.chat.completions.stream_raw(
      model: ENV.fetch("STOGAS_MODEL"),
      messages: [{role: "user", content: "Say hello in one sentence."}]
    )
    stream.each do |chunk|
      chunk.choices.each { |choice| print(choice.delta.content) if choice.delta.content }
    end
  ensure
    stream&.close
    http.close
    transport&.close
  end
end
