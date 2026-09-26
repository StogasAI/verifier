const std = @import("std");
const native = @import("transport.zig");
const c = native.c;
const allocator = std.heap.page_allocator;

var cancelled: c.sig_atomic_t = 0;
fn isCancelled() bool {
    const value: *volatile c.sig_atomic_t = &cancelled;
    return value.* != 0;
}
fn cancel(_: c_int) callconv(.c) void {
    const value: *volatile c.sig_atomic_t = &cancelled;
    value.* = 1;
}
fn progress(_: ?*anyopaque, _: c.curl_off_t, _: c.curl_off_t, _: c.curl_off_t, _: c.curl_off_t) callconv(.c) c_int {
    return if (isCancelled()) 1 else 0;
}

fn printContent(bytes: []const u8, field: []const u8) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object or parsed.value.object.contains("error")) return error.InvalidResponse;
    const choices = parsed.value.object.get("choices") orelse return;
    if (choices != .array) return error.InvalidResponse;
    for (choices.array.items) |choice| {
        if (choice != .object) return error.InvalidResponse;
        const message = choice.object.get(field) orelse continue;
        if (message != .object) continue;
        const content = message.object.get("content") orelse continue;
        if (content == .string) {
            if (c.fwrite(content.string.ptr, 1, content.string.len, c.stdout) != content.string.len)
                return error.OutputFailed;
        }
    }
    if (c.fflush(c.stdout) != 0) return error.OutputFailed;
}

const Response = struct {
    http: *c.CURL,
    streaming: bool,
    line: std.ArrayList(u8) = .empty,
    data: std.ArrayList(u8) = .empty,
    event_size: usize = 0,
    has_data: bool = false,
    complete: bool = false,
    skip_lf: bool = false,

    fn deinit(self: *Response) void {
        self.line.deinit(allocator);
        self.data.deinit(allocator);
    }

    fn finishLine(self: *Response) !void {
        defer self.line.clearRetainingCapacity();
        if (self.line.items.len == 0) {
            if (self.has_data) {
                if (self.complete) return error.DataAfterCompletion;
                if (std.mem.eql(u8, self.data.items, "[DONE]")) self.complete = true else try printContent(self.data.items, "delta");
            }
            self.data.clearRetainingCapacity();
            self.event_size = 0;
            self.has_data = false;
        } else {
            const colon = std.mem.indexOfScalar(u8, self.line.items, ':') orelse self.line.items.len;
            if (!std.mem.eql(u8, self.line.items[0..colon], "data")) return;
            var value = self.line.items[@min(colon + 1, self.line.items.len)..];
            if (std.mem.startsWith(u8, value, " ")) value = value[1..];
            if (self.has_data) try self.data.append(allocator, '\n');
            try self.data.appendSlice(allocator, value);
            self.has_data = true;
        }
    }

    fn feed(self: *Response, bytes: []const u8) !void {
        if (!self.streaming) {
            if (bytes.len > 32 * 1024 * 1024 - self.data.items.len) return error.ResponseTooLarge;
            return self.data.appendSlice(allocator, bytes);
        }
        for (bytes) |byte| {
            if (self.skip_lf and byte == '\n') {
                self.skip_lf = false;
                continue;
            }
            self.skip_lf = byte == '\r';
            if (byte == '\r' or byte == '\n') try self.finishLine() else {
                self.event_size += 1;
                if (self.event_size > 8 * 1024 * 1024) return error.EventTooLarge;
                try self.line.append(allocator, byte);
            }
        }
    }
};

fn receive(bytes: [*c]u8, size: usize, count: usize, context: ?*anyopaque) callconv(.c) usize {
    const response: *Response = @ptrCast(@alignCast(context orelse return 0));
    const length = std.math.mul(usize, size, count) catch return 0;
    var status: c_long = 0;
    if (c.curl_easy_getinfo(response.http, c.CURLINFO_RESPONSE_CODE, &status) != c.CURLE_OK or
        status != 200 or isCancelled()) return 0;
    response.feed(bytes[0..length]) catch return 0;
    return length;
}

fn request(base: []const u8, key: []const u8, model: []const u8, streaming: bool) !void {
    const uri = try std.Uri.parse(base);
    const host = if (uri.host) |value| switch (value) {
        .raw, .percent_encoded => |text| text,
    } else "";
    if (!std.mem.eql(u8, uri.scheme, "http") or uri.host == null or
        !std.mem.eql(u8, host, "127.0.0.1") or uri.user != null)
        return error.ExpectedPrivateURL;
    if (key.len == 0 or model.len == 0 or std.mem.indexOfAny(u8, key, "\r\n") != null)
        return error.MissingConfiguration;
    const url = try std.fmt.allocPrintSentinel(allocator, "{s}/chat/completions", .{base}, 0);
    defer allocator.free(url);
    const token = try allocator.dupeZ(u8, key);
    defer allocator.free(token);
    const body = try std.json.Stringify.valueAlloc(allocator, .{
        .model = model,
        .stream = streaming,
        .messages = .{.{ .role = "user", .content = "Say hello in one sentence." }},
    }, .{});
    defer allocator.free(body);
    const http = c.curl_easy_init() orelse return error.HTTPUnavailable;
    defer c.curl_easy_cleanup(http);
    const headers = c.curl_slist_append(null, "Content-Type: application/json") orelse return error.OutOfMemory;
    defer c.curl_slist_free_all(headers);
    var response = Response{ .http = http, .streaming = streaming };
    defer response.deinit();
    _ = c.curl_easy_setopt(http, c.CURLOPT_URL, url.ptr);
    _ = c.curl_easy_setopt(http, c.CURLOPT_PROXY, @as([*:0]const u8, ""));
    _ = c.curl_easy_setopt(http, c.CURLOPT_FOLLOWLOCATION, @as(c_long, 0));
    _ = c.curl_easy_setopt(http, c.CURLOPT_HTTPAUTH, @as(c_long, c.CURLAUTH_BEARER));
    _ = c.curl_easy_setopt(http, c.CURLOPT_XOAUTH2_BEARER, token.ptr);
    _ = c.curl_easy_setopt(http, c.CURLOPT_HTTPHEADER, headers);
    _ = c.curl_easy_setopt(http, c.CURLOPT_POSTFIELDSIZE_LARGE, @as(c.curl_off_t, @intCast(body.len)));
    _ = c.curl_easy_setopt(http, c.CURLOPT_POSTFIELDS, body.ptr);
    _ = c.curl_easy_setopt(http, c.CURLOPT_CONNECTTIMEOUT, @as(c_long, 15));
    _ = c.curl_easy_setopt(http, c.CURLOPT_TIMEOUT, @as(c_long, 45 * 60));
    _ = c.curl_easy_setopt(http, c.CURLOPT_NOSIGNAL, @as(c_long, 1));
    _ = c.curl_easy_setopt(http, c.CURLOPT_NOPROGRESS, @as(c_long, 0));
    _ = c.curl_easy_setopt(http, c.CURLOPT_XFERINFOFUNCTION, &progress);
    _ = c.curl_easy_setopt(http, c.CURLOPT_WRITEFUNCTION, &receive);
    _ = c.curl_easy_setopt(http, c.CURLOPT_WRITEDATA, &response);
    const outcome = c.curl_easy_perform(http);
    var status: c_long = 0;
    _ = c.curl_easy_getinfo(http, c.CURLINFO_RESPONSE_CODE, &status);
    if (outcome != c.CURLE_OK or status != 200 or isCancelled()) return error.IncompleteRequest;
    if (streaming) {
        if (!response.complete or response.has_data or response.line.items.len != 0) return error.IncompleteStream;
    } else try printContent(response.data.items, "message");
    _ = c.puts("");
}

fn run(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const streaming = if (args.len == 1) true else if (args.len == 2 and std.mem.eql(u8, args[1], "--no-stream"))
        false
    else
        return error.InvalidArguments;
    if (c.curl_global_init(c.CURL_GLOBAL_DEFAULT) != c.CURLE_OK) return error.HTTPUnavailable;
    defer c.curl_global_cleanup();
    _ = c.signal(c.SIGINT, &cancel);
    const key = init.environ_map.get("STOGAS_API_KEY") orelse return error.MissingKey;
    const model = init.environ_map.get("STOGAS_MODEL") orelse return error.MissingModel;
    if (init.environ_map.get("STOGAS_BASE_URL")) |base| return request(base, key, model, streaming);
    var transport = try native.Transport.init(allocator, "{}");
    defer transport.deinit();
    try request(transport.base_url, key, model, streaming);
}

pub fn main(init: std.process.Init) void {
    run(init) catch {
        std.debug.print("Request failed or incomplete. Do not replay automatically.\n", .{});
        std.process.exit(1);
    };
}
