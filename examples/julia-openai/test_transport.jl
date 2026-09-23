using Test
include("transport.jl")

path = only(ARGS)
transport = StogasNative.Transport(path; configuration=Dict("environment"=>"staging", "security"=>"e2ee"))
@test startswith(transport.base_url, "http://127.0.0.1:")
close(transport)
close(transport)
@test transport.handle == C_NULL
@test_throws ErrorException StogasNative.Transport(path; configuration=Dict("security"=>"unknown"))
close(StogasNative.Transport(path; configuration=Dict("environment"=>"staging")))
println("native ownership and configuration passed")
