package.path = (arg[0]:match("^(.*[/\\])") or "./") .. "?.lua;" .. package.path
local curl = require "cURL.safe"
local json = require "cjson.safe"
json.decode_invalid_numbers(false)
local start_transport = require "transport"

local transport, http
local ok = pcall(function()
    local streaming = arg[1] ~= "--no-stream"
    assert(not arg[2] and (not arg[1] or not streaming), "Unknown argument")
    local key, model = os.getenv("STOGAS_API_KEY"), os.getenv("STOGAS_MODEL")
    assert(key and key ~= "" and not key:find("[\r\n]") and model and model ~= "", "Set key and model")
    local base = os.getenv("STOGAS_BASE_URL")
    if not base then
        transport = start_transport(assert(os.getenv("STOGAS_VERIFIER_LIBRARY")))
        base = transport.base_url
    end
    assert(base:match("^http://127%.0%.0%.1:%d+/"), "Expected the private loopback URL")
    local pending, data, completed, after_cr = "", {}, false, false
    local event_bytes, body_bytes, body = 0, 0, {}
    local function print_content(payload, field)
        local value = assert(json.decode(payload), "Invalid JSON")
        assert(type(value) == "table" and not value.error, "Request failed")
        for _, choice in ipairs(value.choices or {}) do
            local content = (choice[field] or {}).content
            if type(content) == "string" then io.write(content) end
        end
        io.flush()
    end
    local function feed(chunk)
        if not streaming then
            body_bytes = body_bytes + #chunk
            assert(body_bytes <= 32 * 1024 * 1024, "Response too large")
            body[#body + 1] = chunk
            return
        end
        if after_cr and chunk:sub(1, 1) == "\n" then chunk = chunk:sub(2) end
        after_cr = chunk:sub(-1) == "\r"
        chunk = chunk:gsub("\r\n", "\n"):gsub("\r", "\n")
        pending = pending .. chunk
        assert(#pending <= 8 * 1024 * 1024, "SSE line too large")
        while true do
            local ending = pending:find("\n", 1, true)
            if not ending then break end
            local line = pending:sub(1, ending - 1)
            pending = pending:sub(ending + 1)
            if line == "" then
                if #data > 0 then
                    assert(not completed, "Data after completion")
                    local payload = table.concat(data, "\n")
                    if payload == "[DONE]" then completed = true
                    else print_content(payload, "delta") end
                end
                data, event_bytes = {}, 0
            elseif line == "data" or line:sub(1, 5) == "data:" then
                local value = line:sub(6):gsub("^ ", "")
                event_bytes = event_bytes + #value + 1
                assert(event_bytes <= 8 * 1024 * 1024, "SSE event too large")
                data[#data + 1] = value
            end
        end
    end
    http = assert(curl.easy({
        url = base .. "/chat/completions", proxy = "", followlocation = false,
        connecttimeout = 15, timeout = 45 * 60, noprogress = false,
        httpheader = {"Authorization: Bearer " .. key, "Content-Type: application/json"},
        postfields = assert(json.encode({model = model, stream = streaming,
            messages = {{role = "user", content = "Say hello in one sentence."}}})),
        -- A callback also lets Lua handle Ctrl+C during a quiet stream.
        progressfunction = function() return true end,
        writefunction = function(chunk)
            if http:getinfo_response_code() ~= 200 then return nil end
            if not pcall(feed, chunk) then return nil end
            return #chunk
        end,
    }))
    assert(http:perform(), "Incomplete HTTP response")
    assert(http:getinfo_response_code() == 200, "Request rejected")
    if streaming then assert(completed and pending == "" and #data == 0, "Incomplete stream")
    else print_content(table.concat(body), "message") end
end)
if http then http:close() end
if transport then transport.close() end
if not ok then
    io.stderr:write("Request failed or incomplete. Do not replay automatically.\n")
    os.exit(1)
end
