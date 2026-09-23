package.path = (arg[0]:match("^(.*[/\\])") or "./") .. "?.lua;" .. package.path
local request = require "http.request"
local json = require "cjson.safe"
local clock = require "cqueues".monotime
local start_transport = require "transport"

local transport, stream
local ok = pcall(function()
    local key, model = os.getenv("STOGAS_API_KEY"), os.getenv("STOGAS_MODEL")
    assert(key and key ~= "" and not key:find("[\r\n]") and model and model ~= "", "Set key and model")
    -- An explicit URL may point to a separately managed verifier CLI.
    local base = os.getenv("STOGAS_BASE_URL")
    if not base then
        transport = start_transport(assert(os.getenv("STOGAS_VERIFIER_LIBRARY")))
        base = transport.base_url
    end
    local req = request.new_from_uri(base .. "/chat/completions")
    req.follow_redirects, req.proxies, req.cookie_store = false, false, false
    req.headers:upsert(":method", "POST")
    req.headers:upsert("authorization", "Bearer " .. key)
    req.headers:upsert("content-type", "application/json")
    req:set_body(assert(json.encode({ model = model, stream = true,
        messages = {{ role = "user", content = "Say hello in one sentence." }} })))
    local deadline = clock() + 45 * 60
    local headers, opened = req:go(deadline - clock())
    assert(headers, "Request failed")
    stream = opened
    local status = tonumber(headers:get(":status"))
    assert(status and status >= 200 and status < 300, "Request rejected")
    local pending, data, completed, after_cr = "", {}, false, false
    local event_bytes = 0
    while true do
        local remaining = deadline - clock()
        assert(remaining > 0, "Request deadline exceeded")
        local chunk, err = stream:get_next_chunk(remaining)
        assert(not err, "Incomplete HTTP response")
        if chunk == nil then break end
        if after_cr and chunk:sub(1, 1) == "\n" then chunk = chunk:sub(2) end
        after_cr = chunk:sub(-1) == "\r"
        chunk = chunk:gsub("\r\n", "\n"):gsub("\r", "\n")
        pending = pending .. chunk
        assert(#pending <= 8 * 1024 * 1024, "SSE line too large")
        while true do
            local ending = pending:find("\n", 1, true)
            if not ending then break end
            local line = pending:sub(1, ending - 1):gsub("\r$", "")
            pending = pending:sub(ending + 1)
            if line == "" and #data > 0 then
                local payload = table.concat(data, "\n")
                data, event_bytes = {}, 0
                if payload == "[DONE]" then completed = true
                else
                    local event = assert(json.decode(payload), "Invalid SSE JSON")
                    assert(type(event) == "table" and (event.error == nil or event.error == json.null), "Stream failed")
                    for _, choice in ipairs(event.choices or {}) do
                        local content = (choice.delta or {}).content
                        if type(content) == "string" then io.write(content) end
                    end
                    io.flush()
                end
            elseif line:sub(1, 5) == "data:" then
                local value = line:sub(6):gsub("^ ", "")
                event_bytes = event_bytes + #value + 1
                assert(event_bytes <= 8 * 1024 * 1024, "SSE event too large")
                data[#data + 1] = value
            end
        end
    end
    assert(completed and pending == "" and #data == 0, "Incomplete stream")
end)
if stream then
    local closed = pcall(stream.shutdown, stream)
    ok = ok and closed
end
if transport then transport.close() end
if not ok then
    io.stderr:write("Request failed or incomplete. Do not replay automatically.\n")
    os.exit(1)
end
