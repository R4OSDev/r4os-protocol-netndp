const std = @import("std");
const sdk = @import("r4os");
const a = sdk.abi;
const native = sdk.native_protocol_view;
const wire = @import("wire.zig");
const neighbors = @import("neighbors.zig");
var api: ?sdk.technical2.Protocol = null;
var cache: neighbors.Cache = .{};
var seed: u32 = 0;
var seed_generation: u64 = 0;
comptime {
    asm (sdk.technical2.protocolEntriesAsm("ndp_init", "ndp_shutdown", "ndp_query", "ndp_dispatch"));
}
export fn ndp_init(raw: *const a.ProtocolApi2) callconv(.c) i32 {
    const view = sdk.technical2.Protocol.init(raw) orelse return a.network_error_backend;
    if (view.function("protocol_dispatch") == null or view.function("link_io") == null) return a.err_no_fn;
    const register = view.function("register_role") orelse return a.err_no_fn;
    const status = view.function("set_status") orelse return a.err_no_fn;
    if (view.function("entropy_fill") == null) return a.err_no_fn;
    if (register("net.ndp", @intFromEnum(a.ProtocolCategory.net), 0) != 0) return a.network_error_backend;
    cache = .{};
    seed_generation = 0;
    api = view;
    return status(@intFromEnum(a.ProtocolState.active), "Bounded ND/NUD; address and router state owned by net.ipv6");
}
export fn ndp_shutdown() callconv(.c) i32 {
    cache = .{};
    api = null;
    seed_generation = 0;
    return 0;
}
export fn ndp_query(out: *a.ProtocolStatus) callconv(.c) i32 {
    out.* = .{ .state = @intFromEnum(if (api != null) a.ProtocolState.active else a.ProtocolState.err) };
    return 0;
}
fn store(comptime T: type, value: *const T, output: *a.ProtocolBuffer) i32 {
    // This copied transport permits unaligned storage. Only the local T has
    // native alignment; the validated byte loan remains within dispatch.
    var policy = native.Policy.versioned(T, 1, .output, .exact);
    policy.alignment = 1;
    const address = native.admit(output, policy, .output) catch return a.network_error_capacity;
    const bytes: [*]u8 = @ptrFromInt(address);
    @memcpy(bytes[0..@sizeOf(T)], std.mem.asBytes(value));
    native.publish(output, policy, @sizeOf(T)) catch return a.network_error_invalid;
    return 0;
}
fn event(value: wire.Event) a.NdpEvent {
    var out: a.NdpEvent = .{ .kind = value.kind, .flags = value.flags, .target = value.target, .mac = value.mac, .router_lifetime_seconds = value.router_lifetime, .reachable_ms = value.reachable_ms, .retransmit_ms = value.retransmit_ms, .mtu = value.mtu, .prefix_count = @intCast(value.prefix_count), .nonce = value.nonce };
    for (value.prefixes[0..value.prefix_count], 0..) |p, i| out.prefixes[i] = .{ .bytes = p.address, .flags = p.flags, .valid_lifetime_seconds = p.valid, .preferred_lifetime_seconds = p.preferred, .prefix_length = p.bits };
    return out;
}
fn action(value: neighbors.Result) a.NdpEvent {
    return .{ .kind = @intFromEnum(value.action), .target = value.target, .mac = value.mac };
}
fn failure(err: anyerror) i32 {
    return switch (err) {
        error.Capacity => a.network_error_capacity,
        error.ClockChanged => a.network_error_clock_changed,
        error.Missing => a.network_error_not_found,
        error.Unsupported => a.network_error_unsupported_policy,
        else => a.network_error_invalid,
    };
}
export fn ndp_dispatch(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) callconv(.c) i32 {
    const view = api orelse return a.network_error_backend;
    if (input.flags != 0 or input.reserved != 0 or input.len > input.capacity or output.flags != 0 or output.reserved != 0) return a.network_error_invalid;
    if (op == a.ndp_op_info) {
        if (input.len != 0) return a.network_error_invalid;
        var identity: a.NetworkLinkInfo = .{};
        const callback = view.function("link_io") orelse return a.err_no_fn;
        const request: a.NetworkLinkRequest = .{ .op = a.network_link_op_identity };
        const code = callback(&request, &identity);
        if (code != 0) return code;
        var info: a.NdpInfo = .{ .provider = identity.provider, .max_links = cache.links.len, .max_neighbors = cache.entries.len, .probes = cache.probes, .timeouts = cache.timeouts };
        for (cache.links) |l| if (l.id != 0) {
            info.active_links += 1;
        };
        for (cache.entries) |e| if (e.state != .free) {
            info.active_neighbors += 1;
        };
        return store(a.NdpInfo, &info, output);
    }
    if (input.data == null or input.len != @sizeOf(a.NdpRequest)) return a.network_error_invalid;
    if (output.data == null or output.capacity < @sizeOf(a.NdpEvent)) return a.network_error_capacity;
    var request: a.NdpRequest = undefined;
    var input_policy = native.Policy.versioned(a.NdpRequest, 1, .input, .exact);
    input_policy.alignment = 1; // copied byte transport, no unaligned native cast
    const input_address = native.admit(input, input_policy, .input) catch return a.network_error_invalid;
    const bytes: [*]const u8 = @ptrFromInt(input_address);
    @memcpy(std.mem.asBytes(&request), bytes[0..@sizeOf(a.NdpRequest)]);
    if (request.version != 1 or request.size != @sizeOf(a.NdpRequest) or request.reserved != 0 or request.reserved1 != 0 or request.interface_id == 0 or request.generation == 0 or request.clock_generation == 0 or request.bytes > 1500 or !std.mem.allEqual(u8, request.payload[request.bytes..], 0)) return a.network_error_invalid;
    if (op != a.ndp_op_link_reset) {
        const source_info = view.function("entropy_source_info") orelse return a.network_error_backend;
        var source: a.EntropySourceInfo = .{};
        if (source_info(&source) != 0 or source.state != a.entropy_state_ready or source.flags & a.entropy_source_flag_registered == 0 or source.generation == 0) return a.network_error_backend;
        if (seed_generation != source.generation) {
            const entropy = view.function("entropy_fill") orelse return a.network_error_backend;
            var value: u32 = 0;
            if (entropy(@ptrCast(&value), @sizeOf(u32)) != @sizeOf(u32)) return a.network_error_backend;
            var after: a.EntropySourceInfo = .{};
            if (source_info(&after) != 0 or after.generation != source.generation or after.state != a.entropy_state_ready) return a.network_error_backend;
            seed = value;
            seed_generation = after.generation;
        }
    }
    var candidate = cache;
    var result: a.NdpEvent = .{};
    if (op == a.ndp_op_handle_rx) {
        if (request.flags & ~@as(u32, 1) != 0 or !wire.zero(request.target) or !wire.unicastMac(request.mac)) return a.network_error_invalid;
        var checksum_request: a.Icmpv6Message = .{ .source = request.source, .destination = request.destination, .bytes = request.bytes };
        @memcpy(checksum_request.payload[0..request.bytes], request.payload[0..request.bytes]);
        var checksum_reply: a.Icmpv6Message = undefined;
        var in_buffer: a.ProtocolBuffer = .{ .data = &checksum_request, .len = @sizeOf(a.Icmpv6Message), .capacity = @sizeOf(a.Icmpv6Message) };
        var out_buffer: a.ProtocolBuffer = .{ .data = &checksum_reply, .capacity = @sizeOf(a.Icmpv6Message) };
        const dispatch = view.function("protocol_dispatch") orelse return a.err_no_fn;
        const code = dispatch("net.icmpv6", "net.icmpv6".len, a.icmpv6_op_parse, &in_buffer, &out_buffer);
        if (code != 0) return code;
        if (out_buffer.len != @sizeOf(a.Icmpv6Message)) return a.network_error_backend;
        const parsed = wire.parse(request.source, request.destination, request.hop_limit, request.flags != 0, request.payload[0..request.bytes]) catch |err| return failure(err);
        candidate.receive(request.interface_id, request.generation, request.clock_generation, request.now_ns, seed, request.source, parsed) catch |err| {
            if (err == error.ClockChanged) cache = candidate;
            return failure(err);
        };
        result = event(parsed);
    } else {
        if (request.bytes != 0 or request.hop_limit != 0 or !wire.zero(request.source) or !wire.zero(request.destination) or !std.mem.allEqual(u8, &request.mac, 0) or request.flags != 0 and !(op == a.ndp_op_confirm and request.flags == 1)) return a.network_error_invalid;
        if ((op == a.ndp_op_tick or op == a.ndp_op_link_reset) and !wire.zero(request.target)) return a.network_error_invalid;
        switch (op) {
            a.ndp_op_resolve => result = action(candidate.resolve(request.interface_id, request.generation, request.clock_generation, request.now_ns, seed, request.target) catch |err| {
                if (err == error.ClockChanged) cache = candidate;
                return failure(err);
            }),
            a.ndp_op_tick => result = action(candidate.tick(request.interface_id, request.generation, request.clock_generation, request.now_ns, seed) catch |err| {
                if (err == error.ClockChanged) cache = candidate;
                return failure(err);
            }),
            a.ndp_op_confirm => candidate.confirm(request.interface_id, request.generation, request.clock_generation, request.now_ns, seed, request.target, request.flags == 1) catch |err| {
                if (err == error.ClockChanged) cache = candidate;
                return failure(err);
            },
            a.ndp_op_link_reset => candidate.reset(request.interface_id, request.generation),
            else => return a.network_error_unsupported_policy,
        }
    }
    cache = candidate;
    return store(a.NdpEvent, &result, output);
}
