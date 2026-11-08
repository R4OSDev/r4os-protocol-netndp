const std = @import("std");
const w = @import("wire.zig");
const n = @import("neighbors.zig");
const ip: w.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
const mac: w.Mac = .{ 2, 3, 4, 5, 6, 7 };
const second: u64 = 1_000_000_000;
test "DAD NS distinguishes nonce, invalid scope, hop, options and fragmentation" {
    var ns: [32]u8 = .{0} ** 32;
    ns[0] = 135;
    @memcpy(ns[8..24], &ip);
    ns[24] = 14;
    ns[25] = 1;
    @memcpy(ns[26..32], &mac);
    const event = try w.parse(.{0} ** 16, w.solicitedNode(ip), 255, false, &ns);
    try std.testing.expectEqual(mac, event.nonce);
    try std.testing.expect(event.flags & w.nonce_present != 0);
    try std.testing.expectError(error.Invalid, w.parse(.{0} ** 16, w.all_nodes, 255, false, &ns));
    try std.testing.expectError(error.Invalid, w.parse(.{0} ** 16, w.solicitedNode(ip), 254, false, &ns));
    try std.testing.expectError(error.Invalid, w.parse(.{0} ** 16, w.solicitedNode(ip), 255, true, &ns));
    ns[24] = 1;
    try std.testing.expectError(error.Invalid, w.parse(.{0} ** 16, w.solicitedNode(ip), 255, false, &ns));
    ns[25] = 0;
    try std.testing.expectError(error.Invalid, w.parse(ip, w.solicitedNode(ip), 255, false, &ns));
}
test "RA parses complete PIO/MTU and fails overflow without clipped success" {
    var ra: [16 + 9 * 32]u8 = .{0} ** (16 + 9 * 32);
    ra[0] = 134;
    ra[6] = 7;
    ra[7] = 8;
    for (0..9) |i| {
        const p = ra[16 + i * 32 ..][0..32];
        p[0] = 3;
        p[1] = 4;
        p[2] = 64;
        p[3] = 0xc0;
        std.mem.writeInt(u32, p[4..8], 7200, .big);
        std.mem.writeInt(u32, p[8..12], 3600, .big);
        p[16] = 0xfd;
        p[23] = @intCast(i);
    }
    const event = try w.parse(ip, w.all_nodes, 255, false, ra[0 .. 16 + 8 * 32]);
    try std.testing.expectEqual(@as(usize, 8), event.prefix_count);
    try std.testing.expectEqual(@as(u32, 1800), event.router_lifetime);
    try std.testing.expectError(error.Capacity, w.parse(ip, w.all_nodes, 255, false, &ra));
    try std.testing.expectError(error.Invalid, w.parse(.{0} ** 16, w.all_nodes, 255, false, &ra));
    ra[17] = 5;
    try std.testing.expectError(error.Invalid, w.parse(ip, w.all_nodes, 255, false, &ra));
}
test "NUD requires real TX acknowledgements and finite timed probes" {
    var cache: n.Cache = .{};
    try std.testing.expectEqual(n.Action.multicast_probe, (try cache.resolve(1, 9, 3, 0, 17, ip)).action);
    // Busy TX did not consume a probe or move its deadline.
    try std.testing.expectEqual(n.Action.multicast_probe, (try cache.tick(1, 9, 3, 10 * second, 17)).action);
    try std.testing.expectEqual(@as(u32, 0), cache.probes);
    for (0..3) |i| {
        const now = (10 + @as(u64, @intCast(i))) * second;
        try cache.confirm(1, 9, 3, now, 17, ip, true);
        try std.testing.expectEqual(n.Action.none, (try cache.resolve(1, 9, 3, now + 1, 17, ip)).action);
        try std.testing.expectEqual(if (i == 2) n.Action.timed_out else n.Action.multicast_probe, (try cache.tick(1, 9, 3, now + second, 17)).action);
    }
    try std.testing.expectEqual(@as(u32, 3), cache.probes);
    try std.testing.expectEqual(@as(u32, 1), cache.timeouts);
}
test "NA override and solicited transitions preserve exact link identity" {
    var cache: n.Cache = .{};
    _ = try cache.resolve(1, 9, 3, 0, 0, ip);
    _ = try cache.resolve(2, 9, 3, 0, 0, ip);
    var na: w.Event = .{ .kind = 136, .target = ip, .mac = mac, .flags = w.mac_present | w.solicited | w.override };
    try cache.receive(1, 9, 3, second, 0, ip, na);
    try std.testing.expectEqual(n.Action.resolved, (try cache.resolve(1, 9, 3, second, 0, ip)).action);
    try std.testing.expectEqual(n.Action.multicast_probe, (try cache.resolve(2, 9, 3, second, 0, ip)).action);
    na.mac[5] = 8;
    na.flags = w.mac_present | w.solicited;
    try cache.receive(1, 9, 3, second, 0, ip, na);
    try std.testing.expectEqual(mac, (try cache.resolve(1, 9, 3, second, 0, ip)).mac);
    try std.testing.expectEqual(n.State.delay, cache.entries[0].state);
    try std.testing.expectEqual(n.Action.unicast_probe, (try cache.tick(1, 9, 3, 6 * second, 0)).action);
    na.flags |= w.override;
    try cache.receive(1, 9, 3, 6 * second, 0, ip, na);
    try std.testing.expectEqual(na.mac, (try cache.resolve(1, 9, 3, 6 * second, 0, ip)).mac);
}
test "clock change resets exact generation; no timer rebasing or unrelated loss" {
    var cache: n.Cache = .{};
    _ = try cache.resolve(1, 9, 3, second, 0, ip);
    _ = try cache.resolve(2, 10, 3, second, 0, ip);
    try std.testing.expectError(error.ClockChanged, cache.tick(1, 9, 4, second, 0));
    try std.testing.expectEqual(n.State.free, cache.entries[0].state);
    try std.testing.expectEqual(n.State.incomplete, cache.entries[1].state);
    try std.testing.expectError(error.ClockChanged, cache.tick(2, 10, 3, second - 1, 0));
}
test "bounded neighbors reject capacity and unsolicited NA creates no entry" {
    var cache: n.Cache = .{};
    try cache.receive(1, 1, 1, 0, 0, ip, .{ .kind = 136, .target = ip, .mac = mac, .flags = w.mac_present | w.solicited });
    try std.testing.expectEqual(n.State.free, cache.entries[0].state);
    for (0..64) |i| {
        var target = ip;
        target[15] = @intCast(i + 1);
        _ = try cache.resolve(1, 1, 1, 0, 0, target);
    }
    var other = ip;
    other[15] = 99;
    try std.testing.expectError(error.Capacity, cache.resolve(1, 1, 1, 0, 0, other));
    cache.reset(1, 2);
    try std.testing.expectEqual(n.State.incomplete, cache.entries[0].state);
    cache.reset(1, 1);
    try std.testing.expectEqual(n.State.free, cache.entries[0].state);
}
