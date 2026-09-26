package.path = (arg[0]:match("^(.*[/\\])") or "./") .. "?.lua;" .. package.path
local start = require "transport"
local library = assert(arg[1], "Pass the staging native library path")
local transport = start(library, { environment = "staging", security = "e2ee" })
assert(transport.base_url:match("^http://127%.0%.0%.1:"))
transport.close()
transport.close()
assert(not pcall(start, library, { security = "unknown" }))
start(library, { environment = "staging" }).close()
collectgarbage()
print("native ownership and configuration passed")
