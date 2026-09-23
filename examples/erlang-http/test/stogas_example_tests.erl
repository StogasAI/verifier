-module(stogas_example_tests).
-include_lib("eunit/include/eunit.hrl").

transport_lifetime_test_() ->
    {timeout, 60, fun() ->
        lists:foreach(fun(Stop) ->
            {ok, Transport} = stogas_transport:start_link(#{
                executable => os:getenv("STOGAS_VERIFY_BIN"),
                args => ["--environment", "staging"]}),
            #{port := Port} = uri_string:parse(stogas_transport:base_url(Transport)),
            {ok, Socket} = gen_tcp:connect({127,0,0,1}, Port, [{active,false}], 1000),
            gen_tcp:close(Socket),
            case Stop of
                close -> stogas_transport:close(Transport);
                crash -> unlink(Transport), exit(Transport, kill)
            end,
            ?assert(closed(Port, erlang:monotonic_time(millisecond) + 7000))
        end, [close, crash])
    end}.

closed(Port, Deadline) ->
    case gen_tcp:connect({127,0,0,1}, Port, [{active,false}], 100) of
        {error, econnrefused} -> true;
        {ok, Socket} ->
            gen_tcp:close(Socket),
            await_closed(Port, Deadline);
        {error, Reason} when Reason =:= econnreset; Reason =:= timeout ->
            % Closing the listener can reset a connect already in progress.
            await_closed(Port, Deadline);
        _ -> false
    end.

await_closed(Port, Deadline) ->
    case erlang:monotonic_time(millisecond) < Deadline of
        true -> timer:sleep(20), closed(Port, Deadline);
        false -> false
    end.

quiet_request_cancellation_test() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, Listener} = gen_tcp:listen(0, [binary, {active,false}, {reuseaddr,true}]),
    {ok, Port} = inet:port(Listener),
    Owner = self(),
    {Server, ServerMonitor} = spawn_monitor(fun() ->
        {ok, Socket} = gen_tcp:accept(Listener),
        {ok, _} = gen_tcp:recv(Socket, 0, 5000),
        Data = <<"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n">>,
        ok = gen_tcp:send(Socket, [
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            integer_to_list(byte_size(Data), 16), "\r\n", Data, "\r\n"]),
        Owner ! request_started,
        Result = gen_tcp:recv(Socket, 0, 4000),
        gen_tcp:close(Socket),
        exit({socket_result, Result})
    end),
    {Request, RequestMonitor} = spawn_monitor(fun() ->
        try stogas_example:request(iolist_to_binary(["http://127.0.0.1:", integer_to_list(Port), "/v1"]),
            <<"test">>, <<"test">>, true)
        catch error:cancelled -> exit(cancelled) end
    end),
    try
        receive request_started -> ok after 5000 -> error(request_did_not_start) end,
        Request ! cancel,
        receive {'DOWN', RequestMonitor, process, Request, cancelled} -> ok
        after 5000 -> error(request_not_cancelled) end,
        receive {'DOWN', ServerMonitor, process, Server, {socket_result, {error, closed}}} -> ok
        after 5000 -> error(connection_not_closed) end
    after
        exit(Request, kill),
        exit(Server, kill),
        gen_tcp:close(Listener)
    end.
