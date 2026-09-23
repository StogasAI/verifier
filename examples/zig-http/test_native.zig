const std = @import("std");
const native = @import("transport.zig");
const socket = @cImport({
    @cInclude("arpa/inet.h");
    @cInclude("unistd.h");
});

fn connect(port: u16) !void {
    const fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    defer _ = socket.close(fd);
    var address: socket.sockaddr_in = std.mem.zeroes(socket.sockaddr_in);
    address.sin_family = socket.AF_INET;
    address.sin_port = socket.htons(port);
    address.sin_addr.s_addr = socket.htonl(0x7f000001);
    if (socket.connect(fd, @ptrCast(&address), @sizeOf(socket.sockaddr_in)) != 0)
        return error.ConnectionFailed;
}

fn useTransport(port: *u16, interrupted: bool) !void {
    var transport = try native.Transport.init(std.testing.allocator, if (interrupted)
        "{\"environment\":\"staging\",\"security\":\"e2ee\"}"
    else
        "{\"environment\":\"staging\",\"security\":\"tls\"}");
    defer transport.deinit();
    port.* = (try std.Uri.parse(transport.base_url)).port orelse return error.MissingPort;
    try connect(port.*);
    if (interrupted) return error.Interrupted;
}

test "native transport releases its listener on normal return and error" {
    var port: u16 = 0;
    try useTransport(&port, false);
    try std.testing.expectError(error.ConnectionFailed, connect(port));
    try std.testing.expectError(error.Interrupted, useTransport(&port, true));
    try std.testing.expectError(error.ConnectionFailed, connect(port));
    try std.testing.expectError(error.TransportUnavailable, native.Transport.init(std.testing.allocator, "{\"security\":\"unknown\"}"));
}
