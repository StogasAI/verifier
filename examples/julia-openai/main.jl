using OpenAI
include("transport.jl")
include("stream.jl")
Base.exit_on_sigint(false) # Let Ctrl+C unwind finally and close the native transport.

function main()
    transport = nothing
    try
        all(arg -> arg == "--no-stream", ARGS) && length(ARGS) <= 1 || error("Invalid arguments")
        key, model = ENV["STOGAS_API_KEY"], ENV["STOGAS_MODEL"]
        !isempty(key) && !isempty(model) && !occursin(r"[\r\n]", key) || error("Set key and model")
        base = get(ENV, "STOGAS_BASE_URL", nothing)
        if isnothing(base)
            transport = StogasNative.Transport(ENV["STOGAS_VERIFIER_LIBRARY"])
            base = transport.base_url
        end
        if "--no-stream" in ARGS
            provider = OpenAI.OpenAIProvider(api_key=key, base_url=base)
            response = create_chat(provider, model,
                [Dict("role" => "user", "content" => "Say hello in one sentence.")];
                http_kwargs = (retry=false, redirect=false, proxy=nothing, readtimeout=45*60))
            print(response.response[:choices][begin][:message][:content])
        else
            stream_chat(base, key, model)
        end
        println()
        return 0
    catch
        println(stderr, "Request failed or incomplete. Do not replay automatically.")
        return 1
    finally
        isnothing(transport) || close(transport)
    end
end
exit(main())
