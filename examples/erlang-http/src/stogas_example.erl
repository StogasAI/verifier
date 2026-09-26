-module(stogas_example).
-export([main/1, request/4]).

main(Args) ->
    {ok, _} = application:ensure_all_started(gun),
    {Transport, Base} = case os:getenv("STOGAS_BASE_URL") of
        false ->
            {ok, Pid} = stogas_transport:start_link(),
            {Pid, stogas_transport:base_url(Pid)};
        Value -> {undefined, list_to_binary(Value)}
    end,
    Result = try
        Stream = case Args of [] -> true; ["--no-stream"] -> false end,
        request(Base, env("STOGAS_API_KEY"), env("STOGAS_MODEL"), Stream),
        io:nl(),
        0
    catch _:_ ->
        io:put_chars(standard_error, "Request failed or incomplete. Do not replay automatically.\n"),
        1
    after
        case Transport of
            undefined -> ok;
            _ -> stogas_transport:close(Transport)
        end
    end,
    halt(Result).

env(Name) ->
    Value = list_to_binary(os:getenv(Name)),
    true = byte_size(Value) > 0,
    nomatch = binary:match(Value, [<<"\r">>, <<"\n">>]),
    Value.

request(Base, Key, Model, Stream) ->
    #{scheme := <<"http">>, host := <<"127.0.0.1">>, port := Port, path := Path} =
        uri_string:parse(Base),
    {ok, Connection} = gun:open({127, 0, 0, 1}, Port,
        #{transport => tcp, protocols => [http], retry => 0}),
    try
        {ok, http} = gun:await_up(Connection),
        Body = json:encode(#{model => Model, stream => Stream,
            messages => [#{role => <<"user">>, content => <<"Say hello in one sentence.">>}]}),
        Ref = gun:post(Connection, <<Path/binary, "/chat/completions">>, [
            {<<"authorization">>, <<"Bearer ", Key/binary>>},
            {<<"content-type">>, <<"application/json">>}
        ], Body),
        Deadline = erlang:monotonic_time(millisecond) + 45 * 60 * 1000,
        try
            {response, nofin, 200, _Headers} = await(Connection, Ref, Deadline),
            case Stream of
                true -> stream(Connection, Ref, Deadline, cow_sse:init(), false);
                false ->
                    Response = json:decode(body(Connection, Ref, Deadline, <<>>)),
                    false = maps:is_key(<<"error">>, Response),
                    [Choice | _] = maps:get(<<"choices">>, Response),
                    print_content(maps:get(<<"message">>, Choice))
            end
        after
            gun:cancel(Connection, Ref)
        end
    after
        gun:close(Connection)
    end.

await(Connection, Ref, Deadline) ->
    Monitor = monitor(process, Connection),
    try
        receive
            cancel -> error(cancelled);
            {gun_response, Connection, Ref, Fin, Status, Headers} ->
                {response, Fin, Status, Headers};
            {gun_data, Connection, Ref, Fin, Data} -> {data, Fin, Data};
            {gun_trailers, Connection, Ref, Headers} -> {trailers, Headers};
            {gun_inform, Connection, Ref, _, _} -> await(Connection, Ref, Deadline);
            {gun_error, Connection, Ref, _} -> error(connection_failed);
            {gun_error, Connection, _} -> error(connection_failed);
            {gun_down, Connection, _, _, _} -> error(connection_failed);
            {'DOWN', Monitor, process, Connection, _} -> error(connection_failed)
        after max(Deadline - erlang:monotonic_time(millisecond), 0) ->
            error(request_timeout)
        end
    after
        demonitor(Monitor, [flush])
    end.

body(Connection, Ref, Deadline, Acc) ->
    case await(Connection, Ref, Deadline) of
        {data, Fin, Data} when byte_size(Acc) + byte_size(Data) =< 32 * 1024 * 1024 ->
            Next = <<Acc/binary, Data/binary>>,
            case Fin of fin -> Next; nofin -> body(Connection, Ref, Deadline, Next) end;
        {trailers, _} -> Acc;
        _ -> error(incomplete_response)
    end.

stream(Connection, Ref, Deadline, Parser, Done) ->
    case await(Connection, Ref, Deadline) of
        {data, Fin, Data} ->
            {Next, Completed} = events(Data, Parser, Done),
            case Fin of
                fin when Completed -> ok;
                fin -> error(incomplete_stream);
                nofin -> stream(Connection, Ref, Deadline, Next, Completed)
            end;
        {trailers, _} when Done -> ok;
        _ -> error(incomplete_stream)
    end.

events(Data, Parser, Done) ->
    case cow_sse:parse(Data, Parser) of
        {more, Next} -> {Next, Done};
        {event, #{data := Payload}, Next} ->
            false = Done,
            case iolist_to_binary(Payload) of
                <<"[DONE]">> -> events(<<>>, Next, true);
                Json ->
                    Event = json:decode(Json),
                    false = maps:is_key(<<"error">>, Event),
                    lists:foreach(fun(Choice) ->
                        print_content(maps:get(<<"delta">>, Choice, #{}))
                    end, maps:get(<<"choices">>, Event, [])),
                    events(<<>>, Next, false)
            end;
        {event, _, Next} -> events(<<>>, Next, Done)
    end.

print_content(Message) ->
    case maps:get(<<"content">>, Message, null) of
        null -> ok;
        Content when is_binary(Content) -> io:put_chars(Content)
    end.
