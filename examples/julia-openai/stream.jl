using HTTP, JSON

function stream_chat(base, key, model)
    body = JSON.json(Dict("model"=>model, "stream"=>true,
        "messages"=>[Dict("role"=>"user", "content"=>"Say hello in one sentence.")]))
    headers = ["Authorization"=>"Bearer $key", "Content-Type"=>"application/json",
        "Content-Length"=>string(ncodeunits(body))]
    HTTP.open("POST", base * "/chat/completions", headers;
        retry=false, redirect=false, proxy=nothing, readtimeout=45*60) do stream
        expired = Ref(false)
        timer = Timer(45*60) do _
            expired[] = true
            close(stream)
        end
        try
            write(stream, body)
            HTTP.closewrite(stream)
            response = HTTP.startread(stream)
            200 <= response.status < 300 || error("Request rejected")
            line, data = UInt8[], UInt8[]
            after_cr, completed = false, false
            while !eof(stream)
                for byte in readavailable(stream)
                    expired[] && error("Request deadline exceeded")
                    skip = after_cr && byte == 0x0a
                    after_cr = byte == 0x0d
                    skip && continue
                    byte == 0x0d && (byte = 0x0a)
                    if byte == 0x0a
                        if isempty(line) && !isempty(data)
                            pop!(data) # remove the last joined newline
                            payload = String(copy(data))
                            empty!(data)
                            isvalid(payload) || error("Invalid UTF-8")
                            completed && error("Data after stream completion")
                            if payload == "[DONE]"
                                completed = true
                            else
                                event = JSON.parse(payload)
                                event isa AbstractDict || error("Invalid SSE object")
                                get(event, "error", nothing) === nothing || error("Stream failed")
                                for choice in get(event, "choices", [])
                                    content = get(get(choice, "delta", Dict()), "content", nothing)
                                    isnothing(content) || print(content)
                                end
                                flush(stdout)
                            end
                        elseif startswith(String(copy(line)), "data:")
                            start = length(line) >= 6 && line[6] == 0x20 ? 7 : 6
                            append!(data, @view line[start:end])
                            push!(data, 0x0a)
                            length(data) <= 8*1024*1024 || error("SSE event too large")
                        end
                        empty!(line)
                    else
                        length(line) < 8*1024*1024 || error("SSE line too large")
                        push!(line, byte)
                    end
                end
            end
            completed && isempty(line) && isempty(data) && !expired[] || error("Incomplete stream")
            HTTP.closeread(stream)
        finally
            close(timer)
        end
    end
end
