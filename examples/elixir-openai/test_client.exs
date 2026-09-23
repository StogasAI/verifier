ExUnit.start()

defmodule StogasClientTest do
  use ExUnit.Case

  test "cancelling a quiet OpenAI stream closes its HTTP request" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listener)
    owner = self()

    server =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, _request} = :gen_tcp.recv(socket, 0, 5000)
        chunk = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            Integer.to_string(byte_size(chunk), 16),
            "\r\n",
            chunk,
            "\r\n"
          ])

        result = await_closed(socket)
        :gen_tcp.close(socket)
        result
      end)

    request =
      Task.async(fn ->
        client = OpenaiEx.new("test") |> OpenaiEx.with_base_url("http://127.0.0.1:#{port}/v1")

        response =
          OpenaiEx.Chat.Completions.create!(
            client,
            OpenaiEx.Chat.Completions.new(
              model: "test",
              messages: [OpenaiEx.ChatMessage.user("test")]
            ),
            stream: true
          )

        Enum.each(response.body_stream, fn _ -> send(owner, :received_chunk) end)
      end)

    try do
      assert_receive :received_chunk, 5000
      Task.shutdown(request, 1000)
      refute Process.alive?(request.pid)
      assert Task.await(server, 5000) == :closed
    after
      Task.shutdown(request, :brutal_kill)
      Task.shutdown(server, :brutal_kill)
      :gen_tcp.close(listener)
    end
  end

  defp await_closed(socket) do
    case :gen_tcp.recv(socket, 0, 4000) do
      {:error, :closed} -> :closed
      {:ok, _} -> await_closed(socket)
      other -> other
    end
  end
end
