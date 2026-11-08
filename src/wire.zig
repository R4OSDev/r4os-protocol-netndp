//! ND syntax only. The caller first verifies the complete ICMPv6 checksum.
//! Parsing is transactional: no neighbor/address state changes on an error.
const std = @import("std");
pub const Address = [16]u8;
pub const Mac = [6]u8;
pub const Error = error{ Invalid, Capacity, Unsupported };
pub const Prefix = struct {
    address: Address = .{0} ** 16,
    flags: u32 = 0,
    valid: u32 = 0,
    preferred: u32 = 0,
    bits: u32 = 0,
};
pub const Event = struct {
    kind: u32 = 0,
    flags: u32 = 0,
    target: Address = .{0} ** 16,
    mac: Mac = .{0} ** 6,
    router_lifetime: u32 = 0,
    reachable_ms: u32 = 0,
    retransmit_ms: u32 = 0,
    mtu: u32 = 0,
    prefix_count: usize = 0,
    prefixes: [8]Prefix = @splat(.{}),
    nonce: [6]u8 = .{0} ** 6,
};
pub const mac_present: u32 = 1;
pub const nonce_present: u32 = 2;
pub const router: u32 = 0x80000000;
pub const solicited: u32 = 0x40000000;
pub const override: u32 = 0x20000000;
pub fn zero(address: Address) bool {
    return std.mem.allEqual(u8, &address, 0);
}
pub fn multicast(address: Address) bool {
    return address[0] == 0xff;
}
pub fn linkLocal(address: Address) bool {
    return address[0] == 0xfe and address[1] & 0xc0 == 0x80;
}
pub fn unicastMac(mac: Mac) bool {
    return mac[0] & 1 == 0 and !std.mem.allEqual(u8, &mac, 0);
}
pub const all_nodes: Address = .{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const all_routers: Address = .{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
pub fn solicitedNode(target: Address) Address {
    var value: Address = .{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0 };
    @memcpy(value[13..], target[13..]);
    return value;
}
fn same(x: Address, y: Address) bool {
    return std.mem.eql(u8, &x, &y);
}
fn be32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}
pub fn parse(source: Address, destination: Address, hop: u32, fragmented: bool, bytes: []const u8) Error!Event {
    if (fragmented or hop != 255 or bytes.len < 8 or bytes[1] != 0 or multicast(source) or zero(destination)) return error.Invalid;
    var event: Event = .{ .kind = bytes[0] };
    var options: usize = 0;
    switch (bytes[0]) {
        133 => {
            if (!zero(source) and !linkLocal(source)) return error.Invalid;
            if (!same(destination, all_routers)) return error.Invalid;
            options = 8;
        },
        134 => {
            if (bytes.len < 16 or !linkLocal(source) or multicast(destination) and !same(destination, all_nodes)) return error.Invalid;
            event.target = source;
            event.router_lifetime = std.mem.readInt(u16, bytes[6..8], .big);
            event.reachable_ms = be32(bytes[8..12]);
            event.retransmit_ms = be32(bytes[12..16]);
            options = 16;
        },
        135, 136 => {
            if (bytes.len < 24) return error.Invalid;
            @memcpy(&event.target, bytes[8..24]);
            if (zero(event.target) or multicast(event.target)) return error.Invalid;
            if (bytes[0] == 135) {
                if (zero(source) and !same(destination, solicitedNode(event.target))) return error.Invalid;
                if (multicast(destination) and !same(destination, solicitedNode(event.target))) return error.Invalid;
            } else {
                event.flags = be32(bytes[4..8]) & (router | solicited | override);
                if (zero(source) or multicast(destination) and event.flags & solicited != 0) return error.Invalid;
            }
            options = 24;
        },
        // Redirects require validated current-router, target and quoted packet
        // ownership. They are explicitly unsupported by this initial host.
        137 => return error.Unsupported,
        else => return error.Unsupported,
    }
    while (options < bytes.len) {
        if (bytes.len - options < 2 or bytes[options + 1] == 0) return error.Invalid;
        const length = @as(usize, bytes[options + 1]) * 8;
        if (length > bytes.len - options) return error.Invalid;
        const option = bytes[options..][0..length];
        switch (option[0]) {
            1, 2 => {
                if (length != 8) return error.Invalid;
                const relevant = option[0] == 1 and event.kind != 136 or option[0] == 2 and event.kind == 136;
                if (relevant) {
                    if (event.flags & mac_present != 0 or zero(source)) return error.Invalid;
                    @memcpy(&event.mac, option[2..8]);
                    if (!unicastMac(event.mac)) return error.Invalid;
                    event.flags |= mac_present;
                }
            },
            3 => if (event.kind == 134) {
                if (length != 32 or option[2] > 128) return error.Invalid;
                // RFC4861 ignores invalid lifetime PIOs without rejecting the
                // independently valid router/other-prefix information.
                const valid = be32(option[4..8]);
                const preferred = be32(option[8..12]);
                if (preferred <= valid) {
                    if (event.prefix_count == event.prefixes.len) return error.Capacity;
                    var prefix: Prefix = .{ .flags = option[3], .valid = valid, .preferred = preferred, .bits = option[2] };
                    @memcpy(&prefix.address, option[16..32]);
                    event.prefixes[event.prefix_count] = prefix;
                    event.prefix_count += 1;
                }
            },
            5 => if (event.kind == 134) {
                if (length != 8 or event.mtu != 0) return error.Invalid;
                const mtu = be32(option[4..8]);
                if (mtu >= 1280) event.mtu = mtu;
            },
            14 => if (event.kind == 135 and zero(source)) {
                if (length != 8 or event.flags & nonce_present != 0) return error.Invalid;
                @memcpy(&event.nonce, option[2..8]);
                event.flags |= nonce_present;
            },
            else => {}, // Unknown ND options are length-checked and ignored.
        }
        options += length;
    }
    return event;
}
