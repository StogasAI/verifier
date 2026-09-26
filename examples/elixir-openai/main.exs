Code.require_file("transport.exs", __DIR__)

defmodule StogasExample do
  def run do
    {transport, base} =
      case System.get_env("STOGAS_BASE_URL") do
        nil ->
          {:ok, pid} = StogasTransport.start_link()
          {pid, StogasTransport.base_url(pid)}

        url ->
          {nil, url}
      end

    try do
      args = System.argv()
      true = args in [[], ["--no-stream"]]
      key = System.fetch_env!("STOGAS_API_KEY")
      model = System.fetch_env!("STOGAS_MODEL")
      true = key != "" and model != "" and not String.contains?(key, ["\r", "\n"])

      client =
        OpenaiEx.new(key)
        |> OpenaiEx.with_base_url(base)
        |> OpenaiEx.with_receive_timeout(45 * 60 * 1000)
        |> OpenaiEx.with_stream_timeout(45 * 60 * 1000)

      request =
        OpenaiEx.Chat.Completions.new(
          model: model,
          messages: [OpenaiEx.ChatMessage.user("Say hello in one sentence.")]
        )

      if args == ["--no-stream"] do
        response = OpenaiEx.Chat.Completions.create!(client, request)
        IO.write(get_in(response, ["choices", Access.at(0), "message", "content"]) || "")
      else
        response = OpenaiEx.Chat.Completions.create!(client, request, stream: true)

        response.body_stream
        |> Stream.flat_map(& &1)
        |> Enum.each(fn %{data: event} ->
          if Map.has_key?(event, "error"), do: raise("Stream failed")

          for choice <- Map.get(event, "choices", []) do
            IO.write(get_in(choice, ["delta", "content"]) || "")
          end
        end)
      end

      IO.puts("")
    rescue
      _ ->
        IO.puts(:stderr, "Request failed or incomplete. Do not replay automatically.")
        exit({:shutdown, 1})
    after
      if transport && Process.alive?(transport), do: StogasTransport.close(transport)
    end
  end
end

StogasExample.run()
