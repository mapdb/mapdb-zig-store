//! Measure StoreDirect's serialization scratch on a real BTree put.
//!
//! `StoreDirect.serialize` (and the WAL/byte-array twins) start from
//! `DataOutput2.init`, capacity 0. Java and Rust pass `size_hint` into
//! `initCapacity` / `with_capacity` instead. This binary does not add that
//! hint and does not change a format. It only records the byte-buffer growth
//! `std.ArrayList` performs while a put serializes a node.
//!
//! Not a `zig build test` dependency. Run: `zig build put-buffer`.

const std = @import("std");
const m = @import("mapdb_zig_store");

const LongFormat = m.ser.long.LongFormat;
const Map = m.btree.BTreeMap(m.StoreDirect, LongFormat, LongFormat);

/// Catalog default (`db/catalog.zig` writes `t#maxNodeSize` = 32).
const max_node: usize = 32;

/// Rust/Java node hint for inline i64 keys and values at this maxNodeSize:
/// `16 + (max+1)*(8+max(8,9)) + 2*8 + 8`. Rust's Direct buffer adds 4.
const hint_bytes: usize = 16 + (max_node + 1) * (8 + 9) + 2 * 8 + 8;

/// First `ArrayList(u8)` growth from capacity 0. Matches
/// `std.array_list.growCapacity`: `new += new/2 + cache_line`.
const first_cap: usize = @max(1, std.atomic.cache_line / @sizeOf(u8));

const Ev = struct {
    op: enum { alloc, remap_ok, remap_fail, resize_ok, resize_fail, free },
    ptr: usize,
    new_ptr: usize,
    old_len: usize,
    new_len: usize,
    align_b: u32,
};

const Trace = struct {
    child: std.mem.Allocator,
    armed: bool = false,
    events: std.ArrayList(Ev) = .empty,
    log_alloc: std.mem.Allocator,

    fn allocator(self: *Trace) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn clear(self: *Trace) void {
        self.events.clearRetainingCapacity();
    }

    fn deinit(self: *Trace) void {
        self.events.deinit(self.log_alloc);
    }

    fn record(self: *Trace, ev: Ev) void {
        if (!self.armed) return;
        self.events.append(self.log_alloc, ev) catch @panic("put-buffer event log OOM");
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Trace = @ptrCast(@alignCast(ctx));
        const p = self.child.vtable.alloc(self.child.ptr, len, alignment, ret_addr) orelse return null;
        self.record(.{
            .op = .alloc,
            .ptr = @intFromPtr(p),
            .new_ptr = @intFromPtr(p),
            .old_len = 0,
            .new_len = len,
            .align_b = @intCast(alignment.toByteUnits()),
        });
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Trace = @ptrCast(@alignCast(ctx));
        const ok = self.child.vtable.resize(self.child.ptr, memory, alignment, new_len, ret_addr);
        self.record(.{
            .op = if (ok) .resize_ok else .resize_fail,
            .ptr = @intFromPtr(memory.ptr),
            .new_ptr = @intFromPtr(memory.ptr),
            .old_len = memory.len,
            .new_len = new_len,
            .align_b = @intCast(alignment.toByteUnits()),
        });
        return ok;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Trace = @ptrCast(@alignCast(ctx));
        if (self.child.vtable.remap(self.child.ptr, memory, alignment, new_len, ret_addr)) |p| {
            self.record(.{
                .op = .remap_ok,
                .ptr = @intFromPtr(memory.ptr),
                .new_ptr = @intFromPtr(p),
                .old_len = memory.len,
                .new_len = new_len,
                .align_b = @intCast(alignment.toByteUnits()),
            });
            return p;
        }
        self.record(.{
            .op = .remap_fail,
            .ptr = @intFromPtr(memory.ptr),
            .new_ptr = 0,
            .old_len = memory.len,
            .new_len = new_len,
            .align_b = @intCast(alignment.toByteUnits()),
        });
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Trace = @ptrCast(@alignCast(ctx));
        self.record(.{
            .op = .free,
            .ptr = @intFromPtr(memory.ptr),
            .new_ptr = 0,
            .old_len = memory.len,
            .new_len = 0,
            .align_b = @intCast(alignment.toByteUnits()),
        });
        self.child.vtable.free(self.child.ptr, memory, alignment, ret_addr);
    }
};

const Chain = struct {
    steps: [16]usize = undefined,
    nsteps: usize = 0,
    grow_remap_ok: usize = 0,
    grow_remap_fail: usize = 0,
    shrink_remap_ok: usize = 0,
    shrink_remap_fail: usize = 0,
    /// Sum of the old requested lengths on growth remaps that failed.
    /// `ArrayList` then copies the logical length, which is ≤ this.
    copy_hi: usize = 0,
    /// Exact bytes copied when a shrink remap fails (`toOwnedSlice`).
    shrink_copy: usize = 0,
    final_len: usize = 0,
    closed: bool = false,

    fn push(self: *Chain, cap: usize) void {
        if (self.nsteps >= self.steps.len) @panic("put-buffer: too many growth steps");
        self.steps[self.nsteps] = cap;
        self.nsteps += 1;
    }
};

const Open = struct { ptr: usize, idx: usize, await_len: ?usize = null };

fn analyze(events: []const Ev, chains: *std.ArrayList(Chain), log_alloc: std.mem.Allocator) !void {
    var open: [64]Open = undefined;
    var nopen: usize = 0;
    for (events) |ev| {
        switch (ev.op) {
            .alloc => {
                var continued = false;
                for (open[0..nopen]) |*slot| {
                    if (slot.await_len) |want| if (want == ev.new_len) {
                        var chain = &chains.items[slot.idx];
                        chain.push(ev.new_len);
                        slot.ptr = ev.ptr;
                        slot.await_len = null;
                        continued = true;
                        break;
                    };
                }
                if (continued) continue;
                if (ev.align_b != 1) continue;
                if (nopen >= open.len) return error.OutOfMemory;
                const idx = chains.items.len;
                try chains.append(log_alloc, .{});
                chains.items[idx].push(ev.new_len);
                chains.items[idx].final_len = ev.new_len;
                open[nopen] = .{ .ptr = ev.ptr, .idx = idx };
                nopen += 1;
            },
            .remap_ok, .resize_ok => {
                const slot = findOpen(open[0..nopen], ev.ptr) orelse continue;
                var chain = &chains.items[slot.idx];
                if (ev.new_len > ev.old_len) {
                    chain.grow_remap_ok += 1;
                    chain.push(ev.new_len);
                } else if (ev.new_len < ev.old_len) {
                    chain.shrink_remap_ok += 1;
                    chain.push(ev.new_len);
                }
                chain.final_len = ev.new_len;
                slot.ptr = ev.new_ptr;
            },
            .remap_fail, .resize_fail => {
                const slot = findOpen(open[0..nopen], ev.ptr) orelse continue;
                var chain = &chains.items[slot.idx];
                if (ev.new_len > ev.old_len) {
                    chain.grow_remap_fail += 1;
                    chain.copy_hi += ev.old_len;
                    slot.await_len = ev.new_len;
                } else if (ev.new_len < ev.old_len) {
                    chain.shrink_remap_fail += 1;
                    chain.shrink_copy += ev.new_len;
                    slot.await_len = ev.new_len;
                }
            },
            .free => {
                const slot_i = findOpenIndex(open[0..nopen], ev.ptr) orelse continue;
                const slot = &open[slot_i];
                if (slot.await_len != null) {
                    // Old block freed after a failed remap; the chain continues
                    // on the allocation that follows.
                    slot.ptr = 0;
                    continue;
                }
                chains.items[slot.idx].closed = true;
                chains.items[slot.idx].final_len = ev.old_len;
                open[slot_i] = open[nopen - 1];
                nopen -= 1;
            },
        }
    }
}

fn findOpen(open: []Open, ptr: usize) ?*Open {
    const i = findOpenIndex(open, ptr) orelse return null;
    return &open[i];
}

fn findOpenIndex(open: []Open, ptr: usize) ?usize {
    for (open, 0..) |slot, i| if (slot.ptr == ptr) return i;
    return null;
}

fn writeCaps(out: *std.Io.Writer, chain: Chain) !void {
    for (chain.steps[0..chain.nsteps], 0..) |step, i| {
        if (i != 0) try out.writeAll(">");
        try out.print("{d}", .{step});
    }
}

fn report(
    out: *std.Io.Writer,
    alloc_name: []const u8,
    window: []const u8,
    trace: *Trace,
    expect_final: ?usize,
) !void {
    var chains: std.ArrayList(Chain) = .empty;
    defer chains.deinit(trace.log_alloc);
    try analyze(trace.events.items, &chains, trace.log_alloc);

    var matched: ?Chain = null;
    var scratch_n: usize = 0;
    for (chains.items) |chain| {
        if (!chain.closed) continue;
        if (chain.nsteps == 0 or chain.steps[0] != first_cap) continue;
        scratch_n += 1;
        try out.print("{s}\t{s}\t{d}\t", .{ alloc_name, window, scratch_n });
        try writeCaps(out, chain);
        try out.print("\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n", .{
            chain.final_len,
            chain.grow_remap_ok,
            chain.grow_remap_fail,
            chain.shrink_remap_ok + chain.shrink_remap_fail,
            chain.copy_hi,
            chain.shrink_copy,
        });
        try out.flush();
        if (expect_final) |want| if (chain.final_len == want) {
            if (matched != null) return error.DuplicateNodeChain;
            matched = chain;
        };
    }
    if (expect_final) |want| {
        const chain = matched orelse {
            std.debug.print("put-buffer: {s} {s} missing final {d}\n", .{ alloc_name, window, want });
            return error.MissingNodeChain;
        };
        if (chain.nsteps < 2) return error.NoGrowth;
        if (chain.steps[0] != first_cap) return error.NotFromEmpty;
    }
}

fn run(out: *std.Io.Writer, alloc_name: []const u8, child: std.mem.Allocator, log_alloc: std.mem.Allocator) !void {
    var trace = Trace{ .child = child, .log_alloc = log_alloc };
    defer trace.deinit();
    const alloc = trace.allocator();

    var store = try m.StoreDirect.init(alloc, true);
    defer store.deinit();

    trace.armed = true;
    trace.clear();
    var map = try Map.create(alloc, &store, .{}, .{}, max_node);
    defer map.deinit();
    try report(out, alloc_name, "create", &trace, 1);

    var i: i64 = 0;
    while (i < 33) : (i += 1) {
        const n: usize = @intCast(i + 1);
        const interesting = n == 1 or n == 32 or n == 33;
        trace.armed = interesting;
        if (interesting) trace.clear();
        _ = try map.put(i, i + 100);
        if (!interesting) continue;
        const expect: ?usize = switch (n) {
            1 => 17,
            32 => 514,
            else => null,
        };
        var window_buf: [16]u8 = undefined;
        const window = std.fmt.bufPrint(&window_buf, "put_n={d}", .{n}) catch unreachable;
        try report(out, alloc_name, window, &trace, expect);
    }
}

pub fn main() !void {
    var log_gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = log_gpa.deinit();
    const log_alloc = log_gpa.allocator();

    var out_buf: [512]u8 = undefined;
    var stdout = std.fs.File.stdout().writerStreaming(&out_buf);
    const out = &stdout.interface;

    try out.print("cache_line\t{d}\n", .{std.atomic.cache_line});
    try out.print("first_cap\t{d}\n", .{first_cap});
    try out.print("hint_i64_max32\t{d}\n", .{hint_bytes});
    try out.print("rust_direct_cap\t{d}\n", .{hint_bytes + 4});
    try out.print("alloc\twindow\tchain\tcaps\tfinal\tgrow_remap_ok\tgrow_remap_fail\tshrinks\tcopy_hi\tshrink_copy\n", .{});
    try out.flush();

    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true, .thread_safe = false }){};
    try run(out, "gpa", gpa.allocator(), log_alloc);
    const leaked = gpa.deinit();
    if (leaked == .leak) return error.Leak;

    try run(out, "page", std.heap.page_allocator, log_alloc);
}
