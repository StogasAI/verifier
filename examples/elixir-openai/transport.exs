defmodule StogasTransport do
  use GenServer

  def start_link(options \\ []), do: GenServer.start_link(__MODULE__, options, timeout: 20_000)
  def base_url(pid), do: GenServer.call(pid, :base_url)
  def close(pid), do: GenServer.stop(pid)

  @impl true
  def init(options) do
    Process.flag(:trap_exit, true)
    executable = Keyword.get(options, :executable) || System.find_executable("stogas-verify")
    if is_nil(executable), do: raise("Install stogas-verify or provide its executable path")

    args =
      ["serve", "--listen", "127.0.0.1:0", "--exit-on-stdin-close"] ++
        Keyword.get(options, :args, [])

    port =
      Port.open(
        {:spawn_executable, String.to_charlist(Path.expand(executable))},
        [:binary, :exit_status, :use_stdio, :hide, {:line, 8192}, {:args, args}]
      )

    try do
      base_url = await_url(port, System.monotonic_time(:millisecond) + 18_000)
      {:ok, %{port: port, base_url: base_url}}
    catch
      kind, reason ->
        if Port.info(port), do: Port.close(port)
        :erlang.raise(kind, reason, __STACKTRACE__)
    end
  end

  defp await_url(port, deadline) do
    receive do
      {^port, {:data, {:eol, "OpenAI base URL: " <> url}}} ->
        %URI{scheme: "http", host: "127.0.0.1", port: port_number} = URI.parse(url)
        true = port_number > 0
        url

      {^port, {:data, {:eol, _}}} ->
        await_url(port, deadline)

      {^port, {:data, {:noeol, _}}} ->
        raise("Oversized verifier startup output")

      {^port, {:exit_status, _}} ->
        raise("Verifier startup failed")

      {:EXIT, ^port, _} ->
        raise("Verifier startup failed")
    after
      max(deadline - System.monotonic_time(:millisecond), 0) ->
        raise("Verifier startup timed out")
    end
  end

  @impl true
  def handle_call(:base_url, _from, state), do: {:reply, state.base_url, state}

  @impl true
  def handle_info({port, {:data, {:eol, _}}}, %{port: port} = state), do: {:noreply, state}
  def handle_info({port, _}, %{port: port} = state), do: {:stop, :verifier_stopped, state}
  def handle_info({:EXIT, port, _}, %{port: port} = state), do: {:stop, :verifier_stopped, state}

  @impl true
  def terminate(_reason, %{port: port}) do
    if Port.info(port), do: Port.close(port)
  end

  @impl true
  def format_status(status) do
    # The loopback URL contains a bearer capability; keep it out of crash reports.
    Map.new(status, fn
      {key, _} when key in [:state, :message, :log] -> {key, :private}
      entry -> entry
    end)
  end
end
