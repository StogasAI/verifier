const std = @import("std");
pub const c = @cImport({
    @cInclude("stogas_verifier.h");
    @cInclude("curl/curl.h");
    @cInclude("stdio.h");
    @cInclude("signal.h");
});

pub const Transport = struct {
    allocator: std.mem.Allocator,
    handle: ?*c.StogasTransport,
    base_url: []u8,

    pub fn init(allocator: std.mem.Allocator, configuration: []const u8) !Transport {
        if (c.stogas_verifier_abi_version() != 1) return error.UnsupportedABI;
        var handle: ?*c.StogasTransport = null;
        const raw = c.stogas_transport_start(configuration.ptr, configuration.len, &handle);
        defer c.stogas_verifier_string_free(raw);
        errdefer c.stogas_transport_free(handle);
        if (raw == null or handle == null) return error.TransportUnavailable;
        const result = try std.json.parseFromSlice(std.json.Value, allocator, std.mem.span(raw), .{});
        defer result.deinit();
        const root = result.value;
        if (root != .object) return error.TransportUnavailable;
        const ok = root.object.get("ok") orelse return error.TransportUnavailable;
        const value = root.object.get("value") orelse return error.TransportUnavailable;
        if (ok != .bool or !ok.bool or value != .object) return error.TransportUnavailable;
        const base = value.object.get("base_url") orelse return error.TransportUnavailable;
        if (base != .string) return error.TransportUnavailable;
        return .{ .allocator = allocator, .handle = handle, .base_url = try allocator.dupe(u8, base.string) };
    }

    pub fn deinit(self: *Transport) void {
        c.stogas_transport_close(self.handle);
        c.stogas_transport_free(self.handle);
        self.allocator.free(self.base_url);
        self.* = undefined;
    }
};
