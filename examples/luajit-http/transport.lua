local ffi = require "ffi"
local json = require "cjson.safe"

ffi.cdef [[
typedef struct StogasTransport StogasTransport;
uint32_t stogas_verifier_abi_version(void);
char *stogas_transport_start(const char *, size_t, StogasTransport **);
void stogas_transport_close(const StogasTransport *);
void stogas_transport_free(StogasTransport *);
void stogas_verifier_string_free(char *);
]]

return function(library, configuration)
    local native = ffi.load(library)
    assert(native.stogas_verifier_abi_version() == 1, "Unsupported native ABI")
    local config = configuration and assert(json.encode(configuration)) or "{}"
    local output = ffi.new("StogasTransport *[1]")
    local raw = native.stogas_transport_start(config, #config, output)
    local result = raw ~= nil and json.decode(ffi.string(raw)) or nil
    native.stogas_verifier_string_free(raw)
    if not result or result.ok ~= true or output[0] == nil or
       type(result.value) ~= "table" or type(result.value.base_url) ~= "string" then
        native.stogas_transport_free(output[0])
        error("Unable to start verified transport")
    end
    local handle = ffi.gc(output[0], function(value) native.stogas_transport_free(value) end)
    return {
        base_url = result.value.base_url,
        close = function()
            if handle ~= nil then
                ffi.gc(handle, nil)
                native.stogas_transport_close(handle)
                native.stogas_transport_free(handle)
                handle = nil
            end
        end,
    }
end
