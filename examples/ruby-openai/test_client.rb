# frozen_string_literal: true
require "minitest/autorun"
require "webrick"
require_relative "main"

class ClientTest < Minitest::Test
  def test_typed_requests_do_not_retry_errors
    [200, 429, 503].each do |status|
      calls = []
      server = WEBrick::HTTPServer.new(Port: 0, BindAddress: "127.0.0.1", Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
      server.mount_proc("/") do |request, response|
        calls << [request.path, request["authorization"], JSON.parse(request.body)]
        response.status = status
        response["Content-Type"] = "application/json"
        response.body = JSON.generate(status == 200 ? {id: "example", object: "chat.completion", created: 1, model: "example", choices: []} : {error: {message: "unavailable", type: "provider_unavailable"}})
      end
      thread = Thread.new { server.start }
      http = local_http
      begin
        client = stogas_client("http://127.0.0.1:#{server.config[:Port]}/cap/v1", "test-key", http)
        request = -> { client.chat.completions.create(model: "example", messages: [{role: "user", content: "hello"}]) }
        if status == 200
          assert_equal "example", request.call.id
        else
          assert_raises(OpenAI::Errors::APIStatusError, &request)
        end
        assert_equal 1, calls.length
        assert_equal "/cap/v1/chat/completions", calls[0][0]
        assert_equal "Bearer test-key", calls[0][1]
        assert_equal "example", calls[0][2]["model"]
      ensure
        http.close
        server.shutdown
        thread.join
      end
    end
  end
end
