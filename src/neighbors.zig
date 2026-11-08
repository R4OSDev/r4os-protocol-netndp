//! Sole bounded neighbor cache. Module dispatch already owns its serial call.
//! A probe advances only after the caller acknowledges real successful TX.
const std = @import("std");
const wire = @import("wire.zig");
const Address = wire.Address;
const Mac = wire.Mac;
pub const State = enum { free, incomplete, reachable, stale, delay, probe };
pub const Action = enum(u32) { none = 0, resolved = 1, multicast_probe = 2, unicast_probe = 3, timed_out = 4 };
pub const Error = error{ Invalid, Capacity, ClockChanged, Missing };
const second: u64 = 1_000_000_000;
const Link = struct {
    id: u32 = 0,
    generation: u64 = 0,
    clock: u32 = 0,
    last: u64 = 0,
    retransmit: u64 = second,
    reachable: u64 = 30 * second,
    random: u32 = 0,
};
pub const Entry = struct {
    state: State = .free,
    id: u32 = 0,
    generation: u64 = 0,
    target: Address = .{0} ** 16,
    mac: Mac = .{0} ** 6,
    due: u64 = 0,
    probes: u32 = 0,
    is_router: bool = false,
};
pub const Result = struct { action: Action = .none, target: Address = .{0} ** 16, mac: Mac = .{0} ** 6 };
pub const Cache = struct {
    links: [8]Link = @splat(.{}),
    entries: [64]Entry = @splat(.{}),
    probes: u32 = 0,
    timeouts: u32 = 0,
    pub fn reset(self: *Cache, id: u32, generation: u64) void {
        for (&self.entries) |*e| if (e.id == id and e.generation == generation) {
            e.* = .{};
        };
        for (&self.links) |*l| if (l.id == id and l.generation == generation) {
            l.* = .{};
        };
    }
    fn link(self: *Cache, id: u32, generation: u64, clock: u32, now: u64, random: u32) Error!*Link {
        if (id == 0 or generation == 0 or clock == 0) return error.Invalid;
        var free: ?*Link = null;
        for (&self.links) |*l| {
            if (l.id == id and l.generation == generation) {
                if (l.clock != clock or now < l.last) {
                    self.reset(id, generation);
                    return error.ClockChanged;
                }
                l.last = now;
                return l;
            }
            if (l.id == 0 and free == null) free = l;
        }
        const l = free orelse return error.Capacity;
        l.* = .{ .id = id, .generation = generation, .clock = clock, .last = now, .random = random, .reachable = (15_000 + @as(u64, random) % 30_001) * 1_000_000 };
        return l;
    }
    fn find(self: *Cache, id: u32, generation: u64, target: Address) ?*Entry {
        for (&self.entries) |*e| if (e.state != .free and e.id == id and e.generation == generation and std.mem.eql(u8, &e.target, &target)) return e;
        return null;
    }
    fn allocate(self: *Cache, id: u32, generation: u64, target: Address) Error!*Entry {
        if (wire.zero(target) or wire.multicast(target)) return error.Invalid;
        if (self.find(id, generation, target)) |e| return e;
        for (&self.entries) |*e| if (e.state == .free) {
            e.* = .{ .state = .incomplete, .id = id, .generation = generation, .target = target };
            return e;
        };
        // Do not evict another caller's incomplete/probing neighbor silently.
        return error.Capacity;
    }
    pub fn receive(self: *Cache, id: u32, generation: u64, clock: u32, now: u64, random: u32, source: Address, event: wire.Event) Error!void {
        const l = try self.link(id, generation, clock, now, random);
        if (event.kind == 134) {
            if (event.retransmit_ms != 0) l.retransmit = @as(u64, event.retransmit_ms) * 1_000_000;
            if (event.reachable_ms != 0 and event.reachable_ms <= 3_600_000) l.reachable = (@as(u64, event.reachable_ms) * (500 + @as(u64, l.random) % 1001)) * 1000;
        }
        if (event.kind == 136) {
            // RFC4861: unsolicited advertisements never create entries.
            const e = self.find(id, generation, event.target) orelse return;
            const has_mac = event.flags & wire.mac_present != 0;
            const changed = has_mac and !std.mem.eql(u8, &e.mac, &event.mac);
            if (e.state == .incomplete) {
                if (!has_mac) return;
                e.mac = event.mac;
                e.state = if (event.flags & wire.solicited != 0) .reachable else .stale;
            } else if (changed and event.flags & wire.override == 0) {
                if (e.state == .reachable) e.state = .stale;
                return;
            } else {
                if (has_mac) e.mac = event.mac;
                if (event.flags & wire.solicited != 0) e.state = .reachable else if (changed) {
                    e.state = .stale;
                }
            }
            e.is_router = event.flags & wire.router != 0;
            if (e.state == .reachable) e.due = now +| l.reachable;
            e.probes = 0;
        } else if (event.flags & wire.mac_present != 0 and !wire.zero(source)) {
            const e = try self.allocate(id, generation, source);
            if (e.state == .incomplete or !std.mem.eql(u8, &e.mac, &event.mac)) {
                e.mac = event.mac;
                e.state = .stale;
                e.probes = 0;
            }
            if (event.kind == 134) e.is_router = true;
        }
    }
    fn action(self: *Cache, e: *Entry, now: u64, sending: bool) Result {
        if (e.state == .reachable and now >= e.due) e.state = .stale;
        if (e.state == .stale and sending) {
            e.state = .delay;
            e.due = now +| 5 * second;
        }
        if (e.state == .delay and now >= e.due) {
            e.state = .probe;
            e.probes = 0;
            e.due = now;
        }
        const result: Result = .{ .target = e.target, .mac = e.mac };
        if ((e.state == .incomplete or e.state == .probe) and now >= e.due) {
            if (e.probes >= 3) {
                var timeout = result;
                timeout.action = .timed_out;
                e.* = .{};
                self.timeouts +|= 1;
                return timeout;
            }
            var probe = result;
            probe.action = if (e.state == .incomplete) .multicast_probe else .unicast_probe;
            return probe;
        }
        if (e.state != .incomplete and e.state != .free) {
            var resolved = result;
            resolved.action = .resolved;
            return resolved;
        }
        return result;
    }
    pub fn resolve(self: *Cache, id: u32, generation: u64, clock: u32, now: u64, random: u32, target: Address) Error!Result {
        _ = try self.link(id, generation, clock, now, random);
        const e = try self.allocate(id, generation, target);
        return self.action(e, now, true);
    }
    pub fn tick(self: *Cache, id: u32, generation: u64, clock: u32, now: u64, random: u32) Error!Result {
        _ = try self.link(id, generation, clock, now, random);
        for (&self.entries) |*e| if (e.state != .free and e.id == id and e.generation == generation) {
            const result = self.action(e, now, false);
            if (@intFromEnum(result.action) >= 2) return result;
        };
        return .{};
    }
    pub fn confirm(self: *Cache, id: u32, generation: u64, clock: u32, now: u64, random: u32, target: Address, probe_sent: bool) Error!void {
        const l = try self.link(id, generation, clock, now, random);
        const e = self.find(id, generation, target) orelse return error.Missing;
        if (probe_sent) {
            if ((e.state != .incomplete and e.state != .probe) or now < e.due or e.probes >= 3) return error.Invalid;
            e.probes += 1;
            e.due = now +| l.retransmit;
            self.probes +|= 1;
        } else {
            if (e.state == .incomplete) return error.Invalid;
            e.state = .reachable;
            e.due = now +| l.reachable;
            e.probes = 0;
        }
    }
};
