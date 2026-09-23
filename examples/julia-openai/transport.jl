module StogasNative
using Libdl, JSON

mutable struct Transport
    library::Ptr{Cvoid}
    handle::Ptr{Cvoid}
    base_url::String
end

function Transport(path; configuration=Dict())
    library = Libdl.dlopen(path)
    version = ccall(Libdl.dlsym(library, :stogas_verifier_abi_version), UInt32, ())
    version == 1 || error("Unsupported verifier ABI")
    json = JSON.json(configuration)
    output = Ref{Ptr{Cvoid}}(C_NULL)
    raw = ccall(Libdl.dlsym(library, :stogas_transport_start), Ptr{UInt8},
        (Cstring, Csize_t, Ref{Ptr{Cvoid}}), json, ncodeunits(json), output)
    try
        raw != C_NULL || error("Unable to start verified transport")
        result = JSON.parse(unsafe_string(raw))
        result.ok === true && output[] != C_NULL || error("Unable to start verified transport")
        return Transport(library, output[], String(result.value.base_url))
    catch
        ccall(Libdl.dlsym(library, :stogas_transport_free), Cvoid, (Ptr{Cvoid},), output[])
        rethrow()
    finally
        ccall(Libdl.dlsym(library, :stogas_verifier_string_free), Cvoid, (Ptr{UInt8},), raw)
    end
end

function Base.close(transport::Transport)
    transport.handle == C_NULL && return
    handle = transport.handle
    transport.handle = C_NULL
    ccall(Libdl.dlsym(transport.library, :stogas_transport_close), Cvoid, (Ptr{Cvoid},), handle)
    ccall(Libdl.dlsym(transport.library, :stogas_transport_free), Cvoid, (Ptr{Cvoid},), handle)
end
end
