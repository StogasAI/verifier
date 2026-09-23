-module(stogas_transport).
-behaviour(gen_server).
-export([start_link/0, start_link/1, base_url/1, close/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, format_status/1]).

start_link() -> start_link(#{}).
start_link(Options) -> gen_server:start_link(?MODULE, Options, [{timeout, 20000}]).
base_url(Pid) -> gen_server:call(Pid, base_url).
close(Pid) -> gen_server:stop(Pid).

init(Options) ->
    process_flag(trap_exit, true),
    Executable = maps:get(executable, Options, os:find_executable("stogas-verify")),
    false =:= Executable andalso error(verifier_not_installed),
    Args = ["serve", "--listen", "127.0.0.1:0", "--exit-on-stdin-close"] ++
        maps:get(args, Options, []),
    Port = open_port({spawn_executable, filename:absname(Executable)},
        [binary, exit_status, use_stdio, hide, {line, 8192}, {args, Args}]),
    try await_url(Port, erlang:monotonic_time(millisecond) + 18000) of
        Url -> {ok, #{port => Port, base_url => Url}}
    catch Class:Reason:Stack ->
        close_port(Port),
        erlang:raise(Class, Reason, Stack)
    end.

await_url(Port, Deadline) ->
    receive
        {Port, {data, {eol, <<"OpenAI base URL: ", Url/binary>>}}} ->
            #{scheme := <<"http">>, host := <<"127.0.0.1">>, port := Number} = uri_string:parse(Url),
            true = Number > 0,
            Url;
        {Port, {data, {eol, _}}} -> await_url(Port, Deadline);
        {Port, {data, {noeol, _}}} -> error(oversized_verifier_output);
        {Port, {exit_status, _}} -> error(verifier_start_failed);
        {'EXIT', Port, _} -> error(verifier_start_failed)
    after max(Deadline - erlang:monotonic_time(millisecond), 0) ->
        error(verifier_start_timeout)
    end.

handle_call(base_url, _From, State) -> {reply, maps:get(base_url, State), State}.
handle_cast(_Message, State) -> {noreply, State}.
handle_info({Port, {data, {eol, _}}}, #{port := Port} = State) -> {noreply, State};
handle_info({Port, _}, #{port := Port} = State) -> {stop, verifier_stopped, State};
handle_info({'EXIT', Port, _}, #{port := Port} = State) -> {stop, verifier_stopped, State}.
terminate(_Reason, #{port := Port}) -> close_port(Port).

close_port(Port) ->
    case erlang:port_info(Port) of
        undefined -> ok;
        _ -> erlang:port_close(Port)
    end.

format_status(Status) ->
    % The private loopback URL is a bearer capability; omit it from crash reports.
    maps:map(fun
        (state, _) -> private;
        (message, _) -> private;
        (log, _) -> private;
        (_, Value) -> Value
    end, Status).
