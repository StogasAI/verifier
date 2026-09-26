Code.require_file("transport.exs", __DIR__)
ExUnit.start()

defmodule StogasTransportTest do
  use ExUnit.Case

  defp start_transport do
    [path] = System.argv()
    StogasTransport.start_link(executable: path, args: ["--environment", "staging"])
  end

  defp closed?(port, deadline) do
    case :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 100) do
      {:error, :econnrefused} ->
        true

      {:ok, socket} ->
        :gen_tcp.close(socket)
        await_closed(port, deadline)

      {:error, reason} when reason in [:econnreset, :timeout] ->
        # Closing the listener can reset a connect already in progress.
        await_closed(port, deadline)

      _ ->
        false
    end
  end

  defp await_closed(port, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      false
    else
      Process.sleep(20)
      closed?(port, deadline)
    end
  end

  test "explicit close and owner crash both stop the child verifier" do
    for stop <- [:close, :crash] do
      {:ok, transport} = start_transport()
      url = URI.parse(StogasTransport.base_url(transport))
      assert url.host == "127.0.0.1"
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, url.port, [:binary, active: false], 1000)
      :gen_tcp.close(socket)

      if stop == :close do
        StogasTransport.close(transport)
      else
        Process.unlink(transport)
        Process.exit(transport, :kill)
      end

      assert closed?(url.port, System.monotonic_time(:millisecond) + 7000),
             "verifier listener survived #{stop}"
    end
  end

  test "unexpected verifier exit is visible to its owner" do
    Process.flag(:trap_exit, true)
    {:ok, transport} = start_transport()
    base = StogasTransport.base_url(transport)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        Port.close(:sys.get_state(transport).port)
        assert_receive {:EXIT, ^transport, :verifier_stopped}, 7000
      end)

    refute log =~ base
  end
end
