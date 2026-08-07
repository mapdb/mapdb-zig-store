//! `StoreDirect` — durable direct store: recid index, free lists, allocator
//! metadata and record data all live on the volume (Java `StoreDirect`,
//! §5). Ported faithfully from `mapdb-rust-store/src/store/direct.rs`; on-volume
//! format v1, magic "MDBS.SD1". The layout was ported from the Rust port's and
//! is not a stabilised cross-engine contract — see `README.md`.
//!
//! v1 read path is the LOCKED baseline (accepted deviation D9.5): reads take the
//! segment read lock. Three lock tiers: `commit_lock` (RwLock, shared per
//! op, exclusive for commit/close/compact/verify; closed re-checked inside),
//! `SegmentLocks` for records, `structural_lock` (Mutex) for allocator state.
//! Never acquire a segment lock while holding the structural lock.
//!
//! Every persisted-derived value is *tainted*: narrowed / range-checked
//! only through `../tainted.zig` and the parity helpers. The allocator validates
//! EVERY persisted link/extent it dereferences on the hot path (open() does not
//! walk the free-recid stack), so a crafted file yields `error.DataCorruption`,
//! never a panic/OOB, in Debug AND ReleaseSafe.
//!
//! ## Inherited-deferred limitations (documented, not fixed here — same as Rust)
//! - **Dirty-marker**: no incremental dirty tracking; commit stamps the
//!   whole header. - **Allocator exception-safety staging**: an allocator
//!   error mid-`write_new_linked` can leave already-allocated chunks orphaned on
//!   the free lists until the next `compact()` (no partial rollback). These match
//!   the Rust port's documented residuals.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const Shared = @import("../shared.zig").Shared;
const tainted = @import("../tainted.zig");

const mod = @import("mod.zig");
const RecordRead = mod.RecordRead;
const AppendResult = mod.AppendResult;
const LeaseTable = mod.LeaseTable;
const SegmentLocks = mod.SegmentLocks;
const SegReadGuard = mod.segment_locks.SegReadGuard;
const SegWriteGuard = mod.segment_locks.SegWriteGuard;
const parity = @import("parity.zig");
const iv = @import("index_val.zig");
const volume = @import("volume.zig");
const Volume = volume.Volume;

// ---------- on-volume geometry ----------

const PAGE_SIZE: u64 = volume.SLICE_SIZE;
/// "MDBS.SD1" big-endian.
const MAGIC: u64 = 0x4D44_4253_2E53_4431;

const O_FEATURES: u64 = 8;
const O_HEAD_CHECKSUM: u64 = 16;
const O_DATA_TAIL: u64 = 24;
const O_MAX_RECID: u64 = 32;
const O_FILE_TAIL: u64 = 40;
const O_FREE_RECID_STACK: u64 = 64;
const O_FREE_DATA_STACKS: u64 = 72;
const MAX_CAP_UNITS: u64 = iv.CAP_MAX_UNITS;
const HEAD_END: u64 = O_FREE_DATA_STACKS + 8 * MAX_CAP_UNITS; // 524336
const ZERO_PAGE_LINK: u64 = HEAD_END;
const ZERO_SLOTS_START: u64 = HEAD_END + 16;
const RECIDS_PER_ZERO_PAGE: u64 = (PAGE_SIZE - ZERO_SLOTS_START) / 8; // 65528
const RECIDS_PER_PAGE: u64 = (PAGE_SIZE - 16) / 8; // 131070

const HEAD_CHECKSUM_SEED: i32 = @bitCast(@as(u32, 0x5D1B_A5E1));

const LONG_STACK_PREF_SIZE: u64 = 160;
const LONG_STACK_MAX_SIZE: u64 = 256;

const LINKED_CHUNK_HDR: usize = 12;
const MAX_CHUNK_DATA: usize = iv.MAX_CAPACITY - LINKED_CHUNK_HDR;
const MAX_VOLUME_SIZE: u64 = 1 << 44;

/// Record state (StoreWAL merge logic; consumed by the WAL store).
pub const STATE_VOID: i32 = 0;
pub const STATE_NULL: i32 = 1;
pub const STATE_LIVE: i32 = 2;

comptime {
    std.debug.assert(HEAD_END == 524336);
    std.debug.assert(ZERO_SLOTS_START == 524352);
    std.debug.assert(RECIDS_PER_ZERO_PAGE == 65528);
    std.debug.assert(RECIDS_PER_PAGE == 131070);
}

/// A record's data offset + validated `used` length.
const OffUsed = struct { off: u64, used: usize };

/// One chunk of a linked record chain.
const Chunk = struct { off: u64, data_len: usize, cap_bytes: usize };

/// A tiling extent (verify oracle).
const Extent = struct { off: u64, size: u64 };

/// A compaction snapshot entry (content owned by `self.alloc`).
const CompactEntry = struct {
    recid: u64,
    prealloc: bool,
    cap_bytes: usize,
    content: ?[]u8,
};

fn freePages(alloc: Allocator, p: *[]u64) void {
    alloc.free(p.*);
}

pub const StoreDirect = struct {
    const Self = @This();
    const SharedPages = Shared([]u64);

    vol: Volume,
    /// Offsets of non-zero index pages, in chain order; copy-on-write.
    index_pages: SharedPages,
    thread_safe: bool,
    structural_lock: std.Thread.Mutex = .{},
    commit_lock: std.Thread.RwLock = .{},
    segs: SegmentLocks,
    closed: std.atomic.Value(bool),
    poisoned: std.atomic.Value(bool),
    /// Bytes on the free-data stacks (guarded by `structural_lock`; monotonic OK).
    free_data_bytes: std.atomic.Value(i64),
    leases: LeaseTable,
    alloc: Allocator,

    // ---------- construction ----------

    /// Anonymous heap-backed store (TCK entry point; matches heap/bytearray init).
    pub fn init(alloc: Allocator, thread_safe: bool) DbError!Self {
        var self = try newEmpty(alloc, try Volume.initHeap(alloc), thread_safe);
        errdefer self.freeAll();
        try self.initCreate();
        return self;
    }

    /// File-backed durable store (mmap volume); created if absent. `path` rel cwd.
    pub fn openFile(alloc: Allocator, path: []const u8, thread_safe: bool) DbError!Self {
        return openFileDiag(alloc, path, thread_safe, null);
    }

    /// Which structural check refused a failed [`openFile`](StoreDirect.openFile).
    ///
    /// Zig errors carry no payload, so every one of the open-path refusals below
    /// is the same bare `error.DataCorruption` — `wal_segments.zig` says the same
    /// thing about its own rows and answers it with a static reason string, and
    /// this is that answer for the direct opener. codex round 1 finding 5 on C5t
    /// is why it exists: the fixture corpus graded its `direct-magic` family as
    /// "the direct opener returned a corruption verdict", which every check in
    /// `initOpen` also satisfies, so the family could not tell the magic word
    /// from a short file or a broken checksum.
    ///
    /// A diagnostic, never a key: nothing branches on it.
    pub const OpenNote = struct { reason: []const u8 = "" };

    pub const D_SHORT_FILE = "store file smaller than the header page";
    pub const D_BAD_MAGIC = "not a MapDB StoreDirect file (bad magic)";
    pub const D_FEATURES = "unsupported feature flags";
    pub const D_HEAD_CHECKSUM = "header checksum mismatch: not closed cleanly, or corrupted";
    pub const D_FILE_TAIL = "bad fileTail";
    pub const D_TRUNCATED = "file shorter than the fileTail its header states";
    pub const D_DATA_TAIL = "bad dataTail geometry";
    pub const D_MAX_RECID = "maxRecid has no addressable index slot";

    /// [`openFile`](StoreDirect.openFile), reporting WHICH check refused.
    ///
    /// **The note is CLEARED on entry**, so what it holds afterwards is this
    /// open's answer or nothing. Round 2 of review found the first draft did
    /// not: a caller reusing an `OpenNote` after a bad-magic refusal saw
    /// `D_BAD_MAGIC` reported for a later refusal from one of the deep walks,
    /// which annotate nothing. A diagnostic that can outlive the refusal it
    /// describes is worse than none, because a predicate reading it cannot tell
    /// the two apart.
    pub fn openFileDiag(
        alloc: Allocator,
        path: []const u8,
        thread_safe: bool,
        note: ?*OpenNote,
    ) DbError!Self {
        if (note) |n| n.* = .{};
        var self = try newEmpty(alloc, try Volume.openFile(alloc, path), thread_safe);
        errdefer self.freeAll();
        const length = try self.vol.length();
        if (length == 0) {
            try self.initCreate();
            // make the new file's directory entry durable
            // (06-decisions.md:271) after its first content sync.
            try self.vol.syncParentDir(path);
        } else if (length < PAGE_SIZE) {
            if (note) |n| n.reason = D_SHORT_FILE;
            return error.DataCorruption; // store file smaller than the header page
        } else {
            try self.vol.ensureAvailable(PAGE_SIZE);
            try self.initOpen(note);
        }
        return self;
    }

    fn newEmpty(alloc: Allocator, vol_in: Volume, thread_safe: bool) DbError!Self {
        var vol = vol_in;
        errdefer vol.deinit();
        const empty_pages = try alloc.alloc(u64, 0);
        var index_pages = SharedPages.init(alloc, empty_pages, freePages) catch |e| {
            alloc.free(empty_pages);
            return e;
        };
        errdefer index_pages.deinit();
        var segs = try SegmentLocks.defaultFor(alloc, thread_safe);
        errdefer segs.deinit();
        return .{
            .vol = vol,
            .index_pages = index_pages,
            .thread_safe = thread_safe,
            .segs = segs,
            .closed = std.atomic.Value(bool).init(false),
            .poisoned = std.atomic.Value(bool).init(false),
            .free_data_bytes = std.atomic.Value(i64).init(0),
            .leases = LeaseTable.init(alloc),
            .alloc = alloc,
        };
    }

    fn freeAll(self: *Self) void {
        self.index_pages.deinit();
        self.vol.deinit();
        self.segs.deinit();
        self.leases.deinit();
    }

    pub fn deinit(self: *Self) void {
        if (!self.closed.load(.acquire)) self.close() catch {};
        self.freeAll();
    }

    // ---------- header init / open ----------

    fn initCreate(self: *Self) DbError!void {
        try self.vol.ensureAvailable(PAGE_SIZE);
        try self.vol.putU64(0, MAGIC);
        try self.vol.putI32(O_FEATURES, 0);
        try self.vol.putI32(O_FEATURES + 4, 0);
        try self.vol.putI32(O_HEAD_CHECKSUM + 4, 0);
        try self.setDataTail(0);
        try self.setMaxRecid(0);
        try self.setFileTail(PAGE_SIZE);
        try self.vol.putU64(O_FREE_RECID_STACK, parity.p4set(0));
        var u: u64 = 1;
        while (u <= MAX_CAP_UNITS) : (u += 1) {
            try self.vol.putU64(masterLinkOffset(u), parity.p4set(0));
        }
        try self.vol.putU64(ZERO_PAGE_LINK, parity.p16set(0));
        try self.vol.putI32(O_HEAD_CHECKSUM, try self.headChecksum());
        try self.vol.sync();
    }

    /// `note` records which check refused, for a caller that must tell these
    /// refusals apart — they are one error tag between them. The deeper walks
    /// this calls (`dataTail`, `maxRecid`, `loadIndexPages`,
    /// `recomputeFreeDataBytes`) have corruption exits of their own and note
    /// NOTHING, so an empty reason beside a `DataCorruption` means "one of the
    /// structural walks, not one of the header checks". A predicate that must
    /// name a specific check therefore fails closed on them, which is the right
    /// way round.
    fn initOpen(self: *Self, note: ?*OpenNote) DbError!void {
        if (try self.vol.length() < PAGE_SIZE) {
            if (note) |n| n.reason = D_SHORT_FILE;
            return error.DataCorruption;
        }
        if (try self.vol.getU64(0) != MAGIC) {
            if (note) |n| n.reason = D_BAD_MAGIC;
            return error.DataCorruption; // bad magic
        }
        if (try self.vol.getI32(O_FEATURES) != 0) {
            if (note) |n| n.reason = D_FEATURES;
            return error.DataCorruption; // unsupported features
        }
        if (try self.vol.getI32(O_HEAD_CHECKSUM) != try self.headChecksum()) {
            if (note) |n| n.reason = D_HEAD_CHECKSUM;
            return error.DataCorruption; // not closed cleanly / corrupted
        }
        const ft = try self.fileTail();
        if (ft < PAGE_SIZE or ft % PAGE_SIZE != 0) {
            if (note) |n| n.reason = D_FILE_TAIL;
            return error.DataCorruption; // bad fileTail
        }
        if (try self.vol.length() < ft) {
            if (note) |n| n.reason = D_TRUNCATED;
            return error.DataCorruption; // truncated
        }
        try self.vol.ensureAvailable(ft);
        // dataTail geometry (see Rust note): a crafted fileTail==dataTail==PAGE_SIZE
        // would make the first allocation write into an unmapped slice → reject.
        const dt = try self.dataTail(); // validates parity
        if (!dataTailGeometryOk(dt, ft)) {
            if (note) |n| n.reason = D_DATA_TAIL;
            return error.DataCorruption; // bad dataTail
        }
        const mr = try self.maxRecid(); // validates parity
        try self.loadIndexPages(ft);
        // maxRecid must have an addressable index slot in the loaded mirror.
        if (!(try self.maxRecidGeometryOk(mr))) {
            if (note) |n| n.reason = D_MAX_RECID;
            return error.DataCorruption; // bad maxRecid
        }
        try self.recomputeFreeDataBytes();
    }

    /// maxRecid geometry invariant, shared by init_open and verify.
    fn maxRecidGeometryOk(self: *Self, max_recid: u64) DbError!bool {
        return max_recid == 0 or (try self.recidToOffset(max_recid)) != null;
    }

    fn loadIndexPages(self: *Self, file_tail: u64) DbError!void {
        var pages: std.ArrayListUnmanaged(u64) = .empty;
        errdefer pages.deinit(self.alloc);
        // detect chain cycles by repeated offset (a
        // one-node self-cycle must not spin/allocate up to a huge fixed bound)
        // and cap the count by the physical maximum derivable from fileTail
        // (unique page-aligned pages cannot exceed fileTail / PAGE_SIZE).
        var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer seen.deinit(self.alloc);
        const max_pages = file_tail / PAGE_SIZE;
        var ptr = ZERO_PAGE_LINK;
        while (true) {
            const page = try parity.p16get(try self.vol.getU64(ptr));
            if (page == 0) break;
            if (page % PAGE_SIZE != 0 or page >= file_tail) return error.DataCorruption; // bad index page pointer
            if ((try seen.fetchPut(self.alloc, page, {})) != null) return error.DataCorruption; // index page chain cycle
            try pages.append(self.alloc, page);
            if (pages.items.len > max_pages) return error.DataCorruption; // more pages than fileTail admits
            ptr = page + 8;
        }
        const owned = try pages.toOwnedSlice(self.alloc);
        try self.index_pages.store(owned);
    }

    /// Mix of every header word the allocator depends on; stamped by commit/close.
    fn headChecksum(self: *Self) DbError!i32 {
        var c: i32 = HEAD_CHECKSUM_SEED;
        var o = O_DATA_TAIL;
        while (o < ZERO_SLOTS_START) : (o += 8) {
            const v = try self.vol.getU64(o);
            c = c *% 31 +% @as(i32, @bitCast(@as(u32, @truncate(v ^ (v >> 32)))));
        }
        return c;
    }

    // ---------- header accessors ----------

    fn dataTail(self: *Self) DbError!u64 {
        return parity.p4get(try self.vol.getU64(O_DATA_TAIL));
    }
    fn setDataTail(self: *Self, v: u64) DbError!void {
        try self.vol.putU64(O_DATA_TAIL, parity.p4set(v));
    }
    fn maxRecid(self: *Self) DbError!u64 {
        return (try parity.p4get(try self.vol.getU64(O_MAX_RECID))) >> 4;
    }
    fn setMaxRecid(self: *Self, v: u64) DbError!void {
        try self.vol.putU64(O_MAX_RECID, parity.p4set(v << 4));
    }
    fn fileTail(self: *Self) DbError!u64 {
        return parity.p16get(try self.vol.getU64(O_FILE_TAIL));
    }
    fn setFileTail(self: *Self, v: u64) DbError!void {
        try self.vol.putU64(O_FILE_TAIL, parity.p16set(v));
    }

    // ---------- recid index ----------

    fn indexPageAt(self: *Self, page_idx: u64) DbError!?u64 {
        var g: SharedPages.Guard = undefined;
        self.index_pages.loadInto(&g);
        defer g.release();
        const pages = g.get().*;
        if (page_idx >= pages.len) return null;
        return pages[@intCast(page_idx)];
    }

    /// Volume offset of the recid's index slot, or `null` when its index page
    /// does not exist.
    fn recidToOffset(self: *Self, recid: u64) DbError!?u64 {
        var r0 = recid - 1;
        if (r0 < RECIDS_PER_ZERO_PAGE) return ZERO_SLOTS_START + r0 * 8;
        r0 -= RECIDS_PER_ZERO_PAGE;
        const page = r0 / RECIDS_PER_PAGE;
        const base = (try self.indexPageAt(page)) orelse return null;
        return base + 16 + (r0 % RECIDS_PER_PAGE) * 8;
    }

    /// Raw (parity1-encoded) index slot; 0 when never allocated / out of range.
    fn rawIndexGet(self: *Self, recid: u64) DbError!u64 {
        if (recid < 1) return 0;
        const off = (try self.recidToOffset(recid)) orelse return 0;
        return self.vol.getU64(off);
    }

    fn indexGetChecked(self: *Self, recid: u64) DbError!u64 {
        const v = try self.rawIndexGet(recid);
        if (v == 0) return error.GetVoid;
        if (!ivParityOk(v)) return error.DataCorruption; // index slot parity broken
        if (!ivSemanticOk(v)) return error.DataCorruption; // capUnits/flags out of domain
        if (iv.capUnits(v) == iv.CAP_DELETED) return error.GetVoid;
        return v;
    }

    fn indexSet(self: *Self, recid: u64, ivval: u64) DbError!void {
        // Rust `.expect()`s a slot here; our guards guarantee one exists, but a
        // missing slot is treated as corruption rather than a panic.
        const off = (try self.recidToOffset(recid)) orelse return error.DataCorruption;
        try self.vol.putU64(off, parity.p1set(ivval));
    }

    /// structural_lock held. Allocate index pages until `recid` has a slot.
    fn ensureIndexCapacityLocked(self: *Self, recid: u64) DbError!void {
        while ((try self.recidToOffset(recid)) == null) {
            try self.allocateNewIndexPageLocked();
        }
    }

    /// structural_lock held.
    fn allocateNewIndexPageLocked(self: *Self) DbError!void {
        // stage EVERY fallible allocation (the grown
        // mirror array and the Shared publication node) BEFORE mutating persistent
        // geometry (fileTail via allocateNewPageLocked) or the link word, and make
        // the publication itself infallible (prepare/publish — `Shared.store`
        // consumes-on-OOM, which double-freed the array). The only fallible steps
        // AFTER the geometry commit are writes to freshly-allocated, in-range,
        // mapped bytes; a failure there means the volume projection is broken, so
        // the store is poisoned rather than left with torn geometry.
        var g: SharedPages.Guard = undefined;
        self.index_pages.loadInto(&g);
        const pages = g.get().*;
        const link_ptr = if (pages.len == 0) ZERO_PAGE_LINK else pages[pages.len - 1] + 8;
        const grown = self.alloc.alloc(u64, pages.len + 1) catch {
            g.release();
            return error.OutOfMemory;
        };
        @memcpy(grown[0..pages.len], pages);
        g.release();
        const prepared = self.index_pages.prepare(grown) catch |e| {
            self.alloc.free(grown);
            return e;
        };
        errdefer self.index_pages.cancel(prepared); // frees node + grown if we bail before publish
        // fileTail advances only on success inside allocateNewPageLocked; a
        // failure here leaves persistent geometry untouched.
        const page = try self.allocateNewPageLocked();
        self.finishIndexPageLocked(page, grown, link_ptr) catch |e| {
            self.poisoned.store(true, .release);
            return e;
        };
        self.index_pages.publish(prepared); // infallible
    }

    /// structural_lock held. Past the fileTail commit point: zero the new page,
    /// write its (empty) forward link, record it in the mirror, and link it from
    /// the previous page. All targets are freshly-allocated, in-range mapped
    /// bytes, so these writes only fail if the projection itself is broken.
    fn finishIndexPageLocked(self: *Self, page: u64, grown: []u64, link_ptr: u64) DbError!void {
        try self.vol.clear(page, page + PAGE_SIZE);
        try self.vol.putU64(page + 8, parity.p16set(0));
        grown[grown.len - 1] = page;
        try self.vol.putU64(link_ptr, parity.p16set(page));
    }

    // ---------- allocator (structural_lock held) ----------

    fn allocateNewPageLocked(self: *Self) DbError!u64 {
        const eof = try self.fileTail();
        const new_eof = try tainted.checkedAdd(u64, eof, PAGE_SIZE);
        if (new_eof > MAX_VOLUME_SIZE) return error.StoreFull;
        try self.vol.ensureAvailable(new_eof);
        try self.setFileTail(new_eof);
        return eof;
    }

    fn allocRecidLocked(self: *Self) DbError!u64 {
        const v = try self.longStackTake(O_FREE_RECID_STACK);
        if (v != 0) {
            const recid = (try parity.p1get(v)) >> 1;
            // A freed recid is always <= maxRecid AND has a live index slot. The
            // reuse branch does not ensure index capacity, so require an
            // addressable slot (a corrupt free-recid value fails gracefully).
            if (recid == 0 or recid > (try self.maxRecid()) or (try self.recidToOffset(recid)) == null)
                return error.DataCorruption; // free recid out of range
            return recid;
        }
        const recid = (try self.maxRecid()) + 1;
        try self.ensureIndexCapacityLocked(recid);
        try self.setMaxRecid(recid);
        return recid;
    }

    fn freeRecidLocked(self: *Self, recid: u64) DbError!void {
        return self.longStackPut(O_FREE_RECID_STACK, parity.p1set(recid << 1));
    }

    /// structural_lock held. `cap_bytes` 16-aligned within [16, MAX_CAPACITY].
    fn allocateDataLocked(self: *Self, cap_bytes: usize, recursive: bool) DbError!u64 {
        std.debug.assert(cap_bytes & 15 == 0 and cap_bytes >= 16 and cap_bytes <= iv.MAX_CAPACITY);
        if (!recursive) {
            const v = try self.longStackTake(masterLinkOffset(@as(u64, cap_bytes) / 16));
            if (v != 0) {
                // reuse a persisted free extent — validate the tiling invariants of
                // its size class before it becomes a written-through record offset.
                // bound the decoded payload in the WIRE
                // domain BEFORE the `<< 3`. A plain shift discards high bits
                // (tainted.zig:53-61), so a corrupt value with bits set above the
                // format max could otherwise alias a live extent's offset and be
                // written through. `off = payload << 3` fits the format iff
                // `payload <= MAX_VOLUME_SIZE >> 3`.
                const payload = try parity.p1get(v);
                if (payload > MAX_VOLUME_SIZE >> 3) return error.DataCorruption; // free-list value out of wire domain
                const off = try tainted.checkedShift(payload, 3);
                const file_tail = try self.fileTail();
                const end = tainted.checkedAdd(u64, off, cap_bytes) catch null;
                if (off < PAGE_SIZE or
                    off & 15 != 0 or
                    (off % PAGE_SIZE) + cap_bytes > PAGE_SIZE or
                    end == null or end.? > file_tail)
                    return error.DataCorruption; // free-list extent out of range
                // addressability backstop before it is written through.
                try self.vol.checkRange(off, cap_bytes);
                _ = self.free_data_bytes.fetchSub(@intCast(cap_bytes), .monotonic);
                return off;
            }
        }
        const tail = try self.dataTail();
        if (tail == 0) {
            const page = try self.allocateNewPageLocked();
            try self.advanceDataTail(page, cap_bytes);
            return page;
        }
        if ((tail % PAGE_SIZE) + cap_bytes <= PAGE_SIZE) {
            try self.advanceDataTail(tail, cap_bytes);
            return tail;
        }
        std.debug.assert(!recursive); // chunk allocation must fit the current page
        const rem = PAGE_SIZE - (tail % PAGE_SIZE);
        const page = try self.allocateNewPageLocked();
        try self.advanceDataTail(page, cap_bytes);
        try self.releaseDataLocked(rem, tail);
        return page;
    }

    fn advanceDataTail(self: *Self, start: u64, cap_bytes: u64) DbError!void {
        const new_tail = try tainted.checkedAdd(u64, start, cap_bytes);
        try self.setDataTail(if (new_tail % PAGE_SIZE == 0) 0 else new_tail);
    }

    fn releaseDataLocked(self: *Self, size_bytes: u64, offset: u64) DbError!void {
        std.debug.assert(size_bytes & 15 == 0 and size_bytes >= 16 and size_bytes / 16 <= MAX_CAP_UNITS);
        std.debug.assert(offset & 15 == 0 and offset >= PAGE_SIZE);
        try self.longStackPut(masterLinkOffset(size_bytes / 16), parity.p1set(offset >> 3));
        _ = self.free_data_bytes.fetchAdd(@intCast(size_bytes), .monotonic);
    }

    // ---------- long stacks (structural_lock held) ----------

    fn putPackedLong(self: *Self, offset: u64, v: u64) DbError!usize {
        const size = packLongSize(v);
        var shift: i64 = @as(i64, @intCast(size - 1)) * 7;
        var p = offset;
        while (shift > 0) : (shift -= 7) {
            try self.vol.putByte(p, @truncate((v >> @intCast(shift)) & 0x7F));
            p += 1;
        }
        try self.vol.putByte(p, @truncate((v & 0x7F) | 0x80));
        return size;
    }

    /// Decode a packed long at `offset`, probing at most `limit` bytes (never
    /// more than the 10-byte format max). A missing terminator within `limit` is
    /// `DataCorruption` — the probe must not run past the validated chunk extent.
    fn getPackedLong(self: *Self, offset: u64, limit: u64) DbError!u64 {
        var ret: u64 = 0;
        var i: u64 = 0;
        const cap = @min(limit, 10);
        while (i < cap) : (i += 1) {
            const b: u64 = try self.vol.getU8(try tainted.checkedAdd(u64, offset, i));
            ret = (ret << 7) | (b & 0x7F);
            if (b & 0x80 != 0) return ret;
        }
        return error.DataCorruption; // unterminated packed long
    }

    /// Validate + load the header of a long-stack chunk whose offset came from a
    /// PERSISTED link word. Returns `(chunk_size, prev_chunk_offset)` after
    /// proving the offset is in the data area, 16-aligned, the size is a legal
    /// chunk size, and the whole chunk extent is addressable in one slice.
    fn loadStackChunkChecked(self: *Self, chunk_offset: u64) DbError!struct { size: u64, prev: u64 } {
        try self.checkStackChunkOff(chunk_offset);
        const hdr = try parity.p4get(try self.vol.getU64(chunk_offset));
        const chunk_size = hdr >> 48;
        if (chunk_size < 16 or chunk_size > LONG_STACK_MAX_SIZE or chunk_size & 15 != 0)
            return error.DataCorruption; // bad long stack chunk size
        try self.vol.checkRange(chunk_offset, chunk_size);
        return .{ .size = chunk_size, .prev = hdr & iv.MOFFSET };
    }

    fn longStackPut(self: *Self, master_link_offset: u64, value: u64) DbError!void {
        std.debug.assert(value != 0 and (value >> 48) == 0);
        const master = try parity.p4get(try self.vol.getU64(master_link_offset));
        if (master == 0) return self.longStackNewChunk(master_link_offset, 0, value);
        const chunk_offset = master & iv.MOFFSET;
        const curr_pos = master >> 48;
        const chunk = try self.loadStackChunkChecked(chunk_offset);
        if (curr_pos < 8 or curr_pos > chunk.size) return error.DataCorruption; // bad long stack position
        const value_size: u64 = packLongSize(value);
        if (curr_pos + value_size > chunk.size)
            return self.longStackNewChunk(master_link_offset, chunk_offset, value);
        _ = try self.putPackedLong(chunk_offset + curr_pos, value);
        try self.vol.putU64(master_link_offset, parity.p4set(((curr_pos + value_size) << 48) | chunk_offset));
    }

    fn longStackNewChunk(self: *Self, master_link_offset: u64, prev_chunk_offset: u64, value: u64) DbError!void {
        const tail = try self.dataTail();
        const chunk_size = if (tail == 0)
            LONG_STACK_PREF_SIZE
        else
            @min(PAGE_SIZE - (tail % PAGE_SIZE), LONG_STACK_PREF_SIZE);
        const value_size: u64 = packLongSize(value);
        std.debug.assert(8 + value_size <= chunk_size);
        const chunk_offset = try self.allocateDataLocked(@intCast(chunk_size), true);
        try self.vol.clear(chunk_offset, chunk_offset + chunk_size);
        try self.vol.putU64(chunk_offset, parity.p4set((chunk_size << 48) | prev_chunk_offset));
        _ = try self.putPackedLong(chunk_offset + 8, value);
        try self.vol.putU64(master_link_offset, parity.p4set(((8 + value_size) << 48) | chunk_offset));
    }

    /// Pop the most recent value (raw, still parity1-encoded), or 0 when empty.
    fn longStackTake(self: *Self, master_link_offset: u64) DbError!u64 {
        const master = try parity.p4get(try self.vol.getU64(master_link_offset));
        if (master == 0) return 0;
        const chunk_offset = master & iv.MOFFSET;
        const chunk = try self.loadStackChunkChecked(chunk_offset);
        const master_pos = master >> 48;
        if (master_pos < 8 or master_pos > chunk.size) return error.DataCorruption; // bad long stack position
        var pos = @max(master_pos -| 1, 8);
        while (pos > 8 and (try self.vol.getU8(chunk_offset + pos - 1)) & 0x80 == 0) {
            pos -= 1;
        }
        const value = try self.getPackedLong(chunk_offset + pos, chunk.size - pos);
        try self.vol.clear(chunk_offset + pos, chunk_offset + pos + packLongSize(value));
        if (pos > 8) {
            try self.vol.putU64(master_link_offset, parity.p4set((pos << 48) | chunk_offset));
            return value;
        }
        // chunk emptied: relink master to the previous chunk, then free this one.
        const prev_chunk_offset = chunk.prev;
        const prev_pos: u64 = if (prev_chunk_offset != 0) blk: {
            const prev = try self.loadStackChunkChecked(prev_chunk_offset);
            break :blk try self.longStackFindEnd(prev_chunk_offset, prev.size);
        } else 0;
        try self.vol.putU64(master_link_offset, parity.p4set((prev_pos << 48) | prev_chunk_offset));
        try self.releaseDataLocked(chunk.size, chunk_offset);
        return value;
    }

    fn longStackFindEnd(self: *Self, chunk_offset: u64, start_pos: u64) DbError!u64 {
        var pos = start_pos;
        while (pos > 8 and (try self.vol.getU8(chunk_offset + pos - 1)) == 0) {
            pos -= 1;
        }
        return pos;
    }

    // ---------- helpers ----------

    fn checkClosed(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
    }

    const CommitRead = struct {
        lock: *std.Thread.RwLock,
        pub fn unlock(self: *CommitRead) void {
            self.lock.unlockShared();
        }
    };

    /// Enter a volume-touching op: shared commit barrier + closed re-check.
    fn mutateEnter(self: *Self) DbError!CommitRead {
        self.commit_lock.lockShared();
        if (self.closed.load(.acquire)) {
            self.commit_lock.unlockShared();
            return error.StoreClosed;
        }
        return .{ .lock = &self.commit_lock };
    }

    fn checkStackChunkOff(self: *Self, off: u64) DbError!void {
        if (off < PAGE_SIZE or off & 15 != 0) return error.DataCorruption; // chunk offset in header/misaligned
        try self.vol.checkRange(off, 8);
    }

    /// Walk a linked-record chain, returning owned `[]Chunk` (caller frees).
    fn linkedChain(self: *Self, ivval: u64) DbError![]Chunk {
        var chunks: std.ArrayListUnmanaged(Chunk) = .empty;
        errdefer chunks.deinit(self.alloc);
        // detect a chunk-chain cycle by repeated offset
        // (a self-referential `next` must fail fast, not walk to a huge fixed
        // bound); the total-length cap (i32::MAX) bounds a legitimate record.
        var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer seen.deinit(self.alloc);
        var cap_units: u64 = iv.capUnits(ivval);
        var off = iv.offset(ivval);
        var total: u64 = 0;
        while (true) {
            const cap_bytes = cap_units * 16;
            if (off < PAGE_SIZE or off & 15 != 0) return error.DataCorruption; // chunk offset in header/misaligned
            if ((try seen.fetchPut(self.alloc, off, {})) != null) return error.DataCorruption; // linked chunk chain cycle
            try self.vol.checkRange(off, cap_bytes);
            const len = try self.vol.getI32(off);
            if (len < 0 or LINKED_CHUNK_HDR + @as(u64, @intCast(len)) > cap_bytes)
                return error.DataCorruption; // linked chunk length out of range
            try chunks.append(self.alloc, .{ .off = off, .data_len = @intCast(len), .cap_bytes = @intCast(cap_bytes) });
            total += @intCast(len);
            if (total > std.math.maxInt(i32))
                return error.DataCorruption; // linked chain too long
            const next = try parity.p1get(try self.vol.getU64(off + 4));
            if (next == 0) break;
            cap_units = next >> 48;
            off = next & iv.MOFFSET;
            if (cap_units < 1 or cap_units > MAX_CAP_UNITS or off < PAGE_SIZE)
                return error.DataCorruption; // bad linked chunk pointer
        }
        return chunks.toOwnedSlice(self.alloc);
    }

    /// Owned reassembled content of a linked record (caller frees via `alloc`).
    fn linkedGet(self: *Self, alloc: Allocator, ivval: u64) DbError![]u8 {
        const chunks = try self.linkedChain(ivval);
        defer self.alloc.free(chunks);
        var total: usize = 0;
        for (chunks) |c| total += c.data_len;
        const out = try alloc.alloc(u8, total);
        errdefer alloc.free(out);
        var p: usize = 0;
        for (chunks) |c| {
            try self.vol.getData(c.off + LINKED_CHUNK_HDR, out[p .. p + c.data_len]);
            p += c.data_len;
        }
        return out;
    }

    /// segment write lock held.
    fn writeNewData(self: *Self, recid: u64, buf: []const u8, cap_bytes: usize, flags: u64) DbError!void {
        const off = blk: {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            break :blk try self.allocateDataLocked(cap_bytes, false);
        };
        try self.vol.putI32(off, @intCast(buf.len));
        try self.vol.putData(off + 4, buf);
        try self.indexSet(recid, iv.compose(@intCast(cap_bytes / 16), off, flags));
    }

    /// segment write lock held. Oversize record → linked chunk chain, tail-first.
    fn writeNewLinked(self: *Self, recid: u64, buf: []const u8) DbError!void {
        const len = buf.len;
        std.debug.assert(needsLinked(len));
        var tail_data = len % MAX_CHUNK_DATA;
        if (tail_data == 0) tail_data = MAX_CHUNK_DATA;
        var pos = len - tail_data;
        var chunk_data_len = tail_data;
        var next_ptr = parity.p1set(0);
        while (true) {
            const cap_bytes = try capBytesFor(LINKED_CHUNK_HDR + chunk_data_len);
            const off = blk: {
                self.structural_lock.lock();
                defer self.structural_lock.unlock();
                break :blk try self.allocateDataLocked(cap_bytes, false);
            };
            try self.vol.putI32(off, @intCast(chunk_data_len));
            try self.vol.putU64(off + 4, next_ptr);
            try self.vol.putData(off + LINKED_CHUNK_HDR, buf[pos .. pos + chunk_data_len]);
            if (pos == 0) {
                try self.indexSet(recid, iv.compose(@intCast(cap_bytes / 16), off, iv.FLAG_LINKED));
                return;
            }
            next_ptr = parity.p1set(((@as(u64, cap_bytes) / 16) << 48) | off);
            chunk_data_len = MAX_CHUNK_DATA;
            pos -= MAX_CHUNK_DATA;
        }
    }

    /// segment write lock held. Free the data area of `iv` if it has one.
    fn releaseOldData(self: *Self, ivval: u64) DbError!void {
        const cap = iv.capUnits(ivval);
        if (cap == iv.CAP_NULL or cap == iv.CAP_DELETED) return;
        if (iv.isLinked(ivval)) {
            const chunks = try self.linkedChain(ivval);
            defer self.alloc.free(chunks);
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            for (chunks) |c| try self.releaseDataLocked(@intCast(c.cap_bytes), c.off);
        } else {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            try self.releaseDataLocked(@as(u64, cap) * 16, iv.offset(ivval));
        }
    }

    /// Read record header of a non-linked live iv, validating `used`.
    fn readUsed(self: *Self, ivval: u64) DbError!OffUsed {
        const off = iv.offset(ivval);
        if (off < PAGE_SIZE or off & 15 != 0) return error.DataCorruption; // offset in header/misaligned
        try self.vol.checkRange(off, 4);
        const used = try self.vol.getI32(off);
        const cap_bytes: i64 = @as(i64, iv.capUnits(ivval)) * 16;
        if (used < 0 or 4 + @as(i64, used) > cap_bytes) return error.DataCorruption; // used beyond capacity
        try self.vol.checkRange(off, 4 + @as(u64, @intCast(used)));
        return .{ .off = off, .used = @intCast(used) };
    }

    // ---------- durability ----------

    fn stampHeaderDurable(self: *Self) DbError!void {
        try self.vol.sync();
        try self.vol.putI32(O_HEAD_CHECKSUM, try self.headChecksum());
        try self.vol.syncHeader();
    }

    fn recomputeFreeDataBytes(self: *Self) DbError!void {
        var total: i64 = 0;
        var u: u64 = 1;
        while (u <= MAX_CAP_UNITS) : (u += 1) {
            var counter = CountCtx{};
            const exts = try self.forEachLongStack(masterLinkOffset(u), &counter);
            self.alloc.free(exts);
            total += @as(i64, @intCast(counter.count)) * (@as(i64, @intCast(u)) * 16);
        }
        self.free_data_bytes.store(total, .monotonic);
    }

    // ---------- long-stack traversal (verify + recompute) ----------

    const CountCtx = struct {
        count: u64 = 0,
        fn onValue(self: *CountCtx, _: u64) DbError!void {
            self.count += 1;
        }
    };

    /// Walk a long stack; invoke `ctx.onValue(parity1-decoded value)` for each
    /// entry; return owned chunk extents `[]Extent` (caller frees). Every chunk
    /// header/size/extent is validated exactly as on the hot path (D4/D5).
    fn forEachLongStack(self: *Self, master_link_offset: u64, ctx: anytype) DbError![]Extent {
        var extents: std.ArrayListUnmanaged(Extent) = .empty;
        errdefer extents.deinit(self.alloc);
        // detect a chunk-chain cycle by repeated offset
        // (a one-node self-cycle must fail fast, not spin to a huge fixed bound)
        // and cap the chunk count physically (min chunk is 16 bytes, so unique
        // chunks cannot exceed fileTail / 16). Traversal failures map to
        // DataCorruption — this walker also runs at open (recomputeFreeDataBytes),
        // where the contract requires DataCorruption; verify()'s wrapper remaps it
        // to VerifyFailed.
        var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer seen.deinit(self.alloc);
        const max_chunks = (try self.fileTail()) / 16;
        const master = try parity.p4get(try self.vol.getU64(master_link_offset));
        if (master == 0) return extents.toOwnedSlice(self.alloc);
        var chunk_offset = master & iv.MOFFSET;
        var pos = master >> 48;
        while (chunk_offset != 0) {
            if ((try seen.fetchPut(self.alloc, chunk_offset, {})) != null) return error.DataCorruption; // long stack chunk cycle
            if (seen.count() > max_chunks) return error.DataCorruption; // more chunks than fileTail admits
            const chunk = try self.loadStackChunkChecked(chunk_offset);
            if (pos < 8 or pos > chunk.size) return error.DataCorruption; // bad long stack position
            try extents.append(self.alloc, .{ .off = chunk_offset, .size = chunk.size });
            var p = chunk_offset + 8;
            const end = chunk_offset + pos;
            while (p < end) {
                if (try self.vol.getU8(p) == 0) return error.DataCorruption; // zero byte in value area
                const raw = try self.getPackedLong(p, end - p);
                p += packLongSize(raw);
                if (p > end) return error.DataCorruption; // value overruns chunk
                try ctx.onValue(try parity.p1get(raw));
            }
            chunk_offset = chunk.prev;
            if (chunk.prev != 0) {
                const prev = try self.loadStackChunkChecked(chunk.prev);
                pos = try self.longStackFindEnd(chunk.prev, prev.size);
            }
        }
        return extents.toOwnedSlice(self.alloc);
    }

    // ---------- WAL hooks (crate-internal, consumed by the WAL store) ----------

    pub fn walPrealloc(self: *Self, recid: u64) DbError!void {
        var c = try self.mutateEnter();
        defer c.unlock();
        {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            try self.ensureIndexCapacityLocked(recid);
            if (recid > try self.maxRecid()) try self.setMaxRecid(recid);
        }
        var wg: SegWriteGuard = undefined;
        self.segs.write(recid, &wg);
        defer wg.unlock();
        const ivval = try self.rawIndexGet(recid);
        if (ivval == 0 or iv.capUnits(ivval) == iv.CAP_DELETED) {
            try self.indexSet(recid, iv.compose(iv.CAP_NULL, 0, iv.FLAG_PREALLOC));
        }
    }

    pub fn walPut(self: *Self, recid: u64, cap_bytes: usize, content: ?[]const u8) DbError!void {
        var c = try self.mutateEnter();
        defer c.unlock();
        {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            try self.ensureIndexCapacityLocked(recid);
            if (recid > try self.maxRecid()) try self.setMaxRecid(recid);
        }
        var wg: SegWriteGuard = undefined;
        self.segs.write(recid, &wg);
        defer wg.unlock();
        const ivval = try self.rawIndexGet(recid);
        if (ivval != 0) {
            if (!ivParityOk(ivval)) return error.DataCorruption; // index slot parity broken
            if (!ivSemanticOk(ivval)) return error.DataCorruption; // capUnits/flags out of domain
            try self.releaseOldData(ivval);
        }
        if (content) |cnt| {
            if (needsLinked(cnt.len)) {
                try self.writeNewLinked(recid, cnt);
            } else {
                const cap = if (cap_bytes == 0) try capBytesFor(4 + cnt.len) else cap_bytes;
                if (cap > iv.MAX_CAPACITY or cap < 4 + cnt.len or cap & 15 != 0)
                    return error.DataCorruption; // bad record capacity
                try self.writeNewData(recid, cnt, cap, 0);
            }
        } else {
            try self.indexSet(recid, iv.compose(iv.CAP_NULL, 0, 0));
        }
    }

    fn rebuildFreeRecidsInner(self: *Self) DbError!void {
        self.structural_lock.lock();
        defer self.structural_lock.unlock();
        const master = try parity.p4get(try self.vol.getU64(O_FREE_RECID_STACK));
        var chunk_offset = master & iv.MOFFSET;
        var chunks: std.ArrayListUnmanaged(Extent) = .empty;
        defer chunks.deinit(self.alloc);
        // offset-set cycle detection + fileTail-derived
        // physical bound (min chunk 16 bytes) instead of a huge fixed guard.
        var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer seen.deinit(self.alloc);
        const max_chunks = (try self.fileTail()) / 16;
        while (chunk_offset != 0) {
            if ((try seen.fetchPut(self.alloc, chunk_offset, {})) != null) return error.DataCorruption; // free recid stack cycle
            if (seen.count() > max_chunks) return error.DataCorruption; // more chunks than fileTail admits
            const chunk = try self.loadStackChunkChecked(chunk_offset);
            try chunks.append(self.alloc, .{ .off = chunk_offset, .size = chunk.size });
            chunk_offset = chunk.prev;
        }
        try self.vol.putU64(O_FREE_RECID_STACK, parity.p4set(0));
        for (chunks.items) |ch| try self.releaseDataLocked(ch.size, ch.off);
        const max = try self.maxRecid();
        var recid: u64 = 1;
        while (recid <= max) : (recid += 1) {
            const ivval = try self.rawIndexGet(recid);
            if (ivval == 0 or iv.capUnits(ivval) == iv.CAP_DELETED) try self.freeRecidLocked(recid);
        }
    }

    /// `delete` for WAL replay: tolerant of a target that is already void or
    /// already deleted, where the public `delete` answers `GetVoid`.
    ///
    /// That tolerance is not laxity, it is the shape a legitimate log takes. A
    /// `T_DELETE` whose record was never established is exactly what a
    /// skipped-append history leaves behind, and the retained log may also begin
    /// after the entry that created the record — the cleaner is allowed to retire
    /// the segments below a mark, so replay routinely sees a delete for a recid it
    /// never saw born. Refusing there would turn an ordinary cleaned log into a
    /// corruption verdict.
    ///
    /// Unlike `delete`, it takes no `assertNotInAction`/`checkClosed`: recovery
    /// runs before the store is open to anyone.
    pub fn walDelete(self: *Self, recid: u64) DbError!void {
        var c = try self.mutateEnter();
        defer c.unlock();
        var wg: SegWriteGuard = undefined;
        self.segs.write(recid, &wg);
        defer wg.unlock();
        const ivval = try self.rawIndexGet(recid);
        if (ivval == 0) return;
        if (!ivParityOk(ivval)) return error.DataCorruption; // index slot parity broken
        if (!ivSemanticOk(ivval)) return error.DataCorruption; // capUnits/flags out of domain
        if (iv.capUnits(ivval) == iv.CAP_DELETED) return;
        try self.releaseOldData(ivval);
        {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            try self.freeRecidLocked(recid);
        }
        try self.indexSet(recid, iv.compose(iv.CAP_DELETED, 0, 0));
    }

    /// Fault injection: breaks the index slot's parity so the next read of it
    /// answers `DataCorruption`.
    ///
    /// The store guards every persisted index value with a parity bit precisely so
    /// a damaged slot cannot be acted on, and that guard is otherwise unreachable
    /// from a test — nothing this store WRITES is ever parity-broken. WAL replay
    /// needs it: an inner-store verdict raised mid-replay has to reach the caller
    /// carrying a reason, and no hand-built WAL image can produce one, so the fault
    /// is injected here instead of asserted to be impossible.
    pub fn corruptIndexSlotForTest(self: *Self, recid: u64) DbError!void {
        const off = (try self.recidToOffset(recid)) orelse return error.DataCorruption;
        // Any single flipped bit inverts the population count, which is the whole
        // parity predicate — so this needs no knowledge of which bit carries it.
        try self.vol.putU64(off, (try self.vol.getU64(off)) ^ 1);
    }

    pub fn recState(self: *Self, recid: u64) DbError!i32 {
        var c = try self.mutateEnter();
        defer c.unlock();
        var rg: SegReadGuard = undefined;
        self.segs.read(recid, &rg);
        defer rg.unlock();
        const ivval = try self.rawIndexGet(recid);
        if (ivval == 0) return STATE_VOID;
        if (!ivParityOk(ivval)) return error.DataCorruption; // index slot parity broken
        if (!ivSemanticOk(ivval)) return error.DataCorruption; // capUnits/flags out of domain
        if (iv.capUnits(ivval) == iv.CAP_DELETED) return STATE_VOID;
        return if (iv.capUnits(ivval) == iv.CAP_NULL) STATE_NULL else STATE_LIVE;
    }

    /// Owned copy of record content, or null for null/P records. GetVoid on N/D.
    pub fn rawGet(self: *Self, alloc: Allocator, recid: u64) DbError!?[]u8 {
        var c = try self.mutateEnter();
        defer c.unlock();
        var rg: SegReadGuard = undefined;
        self.segs.read(recid, &rg);
        defer rg.unlock();
        const ivval = try self.indexGetChecked(recid);
        if (iv.capUnits(ivval) == iv.CAP_NULL) return null;
        if (iv.isLinked(ivval)) return try self.linkedGet(alloc, ivval);
        const ou = try self.readUsed(ivval);
        const r = try alloc.alloc(u8, ou.used);
        errdefer alloc.free(r);
        try self.vol.getData(ou.off + 4, r);
        return r;
    }

    /// Rebuild the free-recid stack from the final index (WAL replay leaves stale
    /// free-list entries after delete-then-reuse histories). Public WAL hook —
    /// mirrors Rust `rebuild_free_recids`.
    pub fn rebuildFreeRecids(self: *Self) DbError!void {
        var c = try self.mutateEnter();
        defer c.unlock();
        try self.rebuildFreeRecidsInner();
    }

    /// Visit every recid that must survive a WAL checkpoint, ascending. For each
    /// live/preallocated/null record the `sink.emit(recid, prealloc, cap_bytes,
    /// content)` callback is invoked; `content` is a temporary owned slice freed
    /// after the callback returns (borrowed by the callback). Deleted/void recids
    /// are skipped. Mirrors Rust `wal_snapshot`. WAL hook.
    pub fn walSnapshot(self: *Self, sink: anytype) DbError!void {
        var c = try self.mutateEnter();
        defer c.unlock();
        const max = blk: {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            break :blk try self.maxRecid();
        };
        var recid: u64 = 1;
        while (recid <= max) : (recid += 1) {
            var emit = false;
            var is_prealloc = false;
            var cap_bytes: usize = 0;
            var content: ?[]u8 = null;
            {
                var rg: SegReadGuard = undefined;
                self.segs.read(recid, &rg);
                defer rg.unlock();
                const ivval = try self.rawIndexGet(recid);
                if (ivval != 0) {
                    if (!ivParityOk(ivval)) return error.DataCorruption; // index slot parity broken
                    if (!ivSemanticOk(ivval)) return error.DataCorruption; // capUnits/flags out of domain
                    const cap = iv.capUnits(ivval);
                    if (cap != iv.CAP_DELETED) {
                        emit = true;
                        if (cap == iv.CAP_NULL) {
                            is_prealloc = iv.isPrealloc(ivval);
                        } else if (iv.isLinked(ivval)) {
                            content = try self.linkedGet(self.alloc, ivval);
                        } else {
                            const ou = try self.readUsed(ivval);
                            const b = try self.alloc.alloc(u8, ou.used);
                            errdefer self.alloc.free(b);
                            try self.vol.getData(ou.off + 4, b);
                            content = b;
                            cap_bytes = @as(usize, cap) * 16;
                        }
                    }
                }
            }
            if (emit) {
                defer if (content) |cc| self.alloc.free(cc);
                try sink.emit(recid, is_prealloc, cap_bytes, content);
            }
        }
    }

    /// Snapshot ONE recid for the WAL cleaner: `sink.emit(prealloc, cap_bytes,
    /// content)` for a live/preallocated/null record (`content` is a temporary
    /// owned slice freed after the callback returns), returning whether the
    /// record exists at all (`false` for a void or deleted slot, where the sink
    /// is not invoked). Mirrors Rust `wal_snapshot_one`. WAL hook.
    ///
    /// Per-recid rather than the whole-store [`walSnapshot`] walk, because the
    /// cleaner re-homes the records it MEETS in the segments it is retiring —
    /// a walk over every recid would be O(store) under the WAL write lock,
    /// which is the pause the incremental cleaner exists to remove. The sink
    /// runs after the per-recid lock is released, so the caller must hold its
    /// own barrier (the WAL write lock) if it needs check-copy-publish to be
    /// one serialized unit. The parity/semantic validation matches
    /// [`walSnapshot`]'s (a deviation from rust in the refusing direction,
    /// recorded there).
    pub fn walSnapshotOne(self: *Self, recid: u64, sink: anytype) DbError!bool {
        var c = try self.mutateEnter();
        defer c.unlock();
        var emit = false;
        var is_prealloc = false;
        var cap_bytes: usize = 0;
        var content: ?[]u8 = null;
        {
            var rg: SegReadGuard = undefined;
            self.segs.read(recid, &rg);
            defer rg.unlock();
            const ivval = try self.rawIndexGet(recid);
            if (ivval != 0) {
                if (!ivParityOk(ivval)) return error.DataCorruption; // index slot parity broken
                if (!ivSemanticOk(ivval)) return error.DataCorruption; // capUnits/flags out of domain
                const cap = iv.capUnits(ivval);
                if (cap != iv.CAP_DELETED) {
                    emit = true;
                    if (cap == iv.CAP_NULL) {
                        is_prealloc = iv.isPrealloc(ivval);
                    } else if (iv.isLinked(ivval)) {
                        content = try self.linkedGet(self.alloc, ivval);
                    } else {
                        const ou = try self.readUsed(ivval);
                        const b = try self.alloc.alloc(u8, ou.used);
                        errdefer self.alloc.free(b);
                        try self.vol.getData(ou.off + 4, b);
                        content = b;
                        cap_bytes = @as(usize, cap) * 16;
                    }
                }
            }
        }
        if (emit) {
            defer if (content) |cc| self.alloc.free(cc);
            try sink.emit(is_prealloc, cap_bytes, content);
        }
        return emit;
    }

    // ---------- verify ----------

    fn verifyLocked(self: *Self) DbError!void {
        const file_tail = try self.fileTail();
        const data_tail = try self.dataTail();
        const max_recid = try self.maxRecid();
        if (file_tail < PAGE_SIZE or file_tail % PAGE_SIZE != 0) return error.VerifyFailed;
        if (!dataTailGeometryOk(data_tail, file_tail)) return error.VerifyFailed;
        if (!(try self.maxRecidGeometryOk(max_recid))) return error.VerifyFailed;

        var index_page_set: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer index_page_set.deinit(self.alloc);
        // index page chain must match the mirror
        {
            var g: SharedPages.Guard = undefined;
            self.index_pages.loadInto(&g);
            defer g.release();
            const mirror = g.get().*;
            var ptr = ZERO_PAGE_LINK;
            var n: usize = 0;
            while (true) {
                const page = try parity.p16get(try self.vol.getU64(ptr));
                if (page == 0) break;
                if (n >= mirror.len or mirror[n] != page) return error.VerifyFailed;
                if (page % PAGE_SIZE != 0 or page >= file_tail) return error.VerifyFailed;
                if ((try index_page_set.fetchPut(self.alloc, page, {})) != null) return error.VerifyFailed;
                ptr = page + 8;
                n += 1;
            }
            if (n != mirror.len) return error.VerifyFailed;
        }

        var extents: std.ArrayListUnmanaged(Extent) = .empty;
        defer extents.deinit(self.alloc);

        var recid: u64 = 1;
        while (recid <= max_recid) : (recid += 1) {
            const ivval = try self.rawIndexGet(recid);
            if (ivval == 0) continue;
            if (!ivParityOk(ivval)) return error.VerifyFailed;
            const cap = iv.capUnits(ivval);
            if (cap == iv.CAP_DELETED or cap == iv.CAP_NULL) {
                if (iv.offset(ivval) != 0) return error.VerifyFailed;
                continue;
            }
            if (iv.isLinked(ivval)) {
                const chunks = try self.linkedChain(ivval);
                defer self.alloc.free(chunks);
                for (chunks) |ch| try extents.append(self.alloc, .{ .off = ch.off, .size = @intCast(ch.cap_bytes) });
            } else {
                const ou = try self.readUsed(ivval);
                _ = ou;
                try extents.append(self.alloc, .{ .off = iv.offset(ivval), .size = @as(u64, cap) * 16 });
            }
        }

        // free recid stack: chunks are extents; each value is a deleted recid.
        var free_recids: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer free_recids.deinit(self.alloc);
        var recid_ctx = FreeRecidCtx{ .store = self, .max_recid = max_recid, .set = &free_recids };
        const recid_chunks = try self.forEachLongStack(O_FREE_RECID_STACK, &recid_ctx);
        defer self.alloc.free(recid_chunks);
        if (recid_ctx.err) |_| return error.VerifyFailed;
        try extents.appendSlice(self.alloc, recid_chunks);

        // free data stacks: chunks AND freed value extents (value<<3, size) tile.
        var free_sum: i64 = 0;
        var u: u64 = 1;
        while (u <= MAX_CAP_UNITS) : (u += 1) {
            const size = u * 16;
            var val_ctx = ValueOffsetCtx{ .store = self, .size = size, .out = &extents, .free_sum = &free_sum };
            const chunk_exts = try self.forEachLongStack(masterLinkOffset(u), &val_ctx);
            defer self.alloc.free(chunk_exts);
            if (val_ctx.err) |e| return e;
            try extents.appendSlice(self.alloc, chunk_exts);
        }
        if (free_sum != self.free_data_bytes.load(.monotonic)) return error.VerifyFailed;

        // geometry + exact tiling
        for (extents.items) |e| {
            if (e.off & 15 != 0 or e.size & 15 != 0 or e.size < 16) return error.VerifyFailed;
            if (e.off < PAGE_SIZE or e.off + e.size > file_tail) return error.VerifyFailed;
            if ((e.off % PAGE_SIZE) + e.size > PAGE_SIZE) return error.VerifyFailed;
            const page = e.off - e.off % PAGE_SIZE;
            if (index_page_set.contains(page)) return error.VerifyFailed;
        }

        var by_page: std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(Extent)) = .empty;
        defer {
            var it = by_page.valueIterator();
            while (it.next()) |list| list.deinit(self.alloc);
            by_page.deinit(self.alloc);
        }
        for (extents.items) |e| {
            const page = e.off - e.off % PAGE_SIZE;
            const gop = try by_page.getOrPut(self.alloc, page);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(self.alloc, e);
        }

        const data_tail_page = if (data_tail == 0) std.math.maxInt(u64) else data_tail - data_tail % PAGE_SIZE;
        var visited: usize = 0; // pages-with-extents covered by the sweep
        var page = PAGE_SIZE;
        while (page < file_tail) : (page += PAGE_SIZE) {
            if (index_page_set.contains(page)) continue;
            const cover_end = if (page == data_tail_page) data_tail else page + PAGE_SIZE;
            var cursor = page;
            if (by_page.getPtr(page)) |list| {
                std.mem.sort(Extent, list.items, {}, extentLess);
                for (list.items) |e| {
                    if (e.off < cursor) return error.VerifyFailed; // overlapping extents
                    if (e.off > cursor) return error.VerifyFailed; // lost extent: gap
                    cursor = e.off + e.size;
                }
                visited += 1;
            }
            if (cursor != cover_end) return error.VerifyFailed; // page not fully covered
        }
        // Every page carrying extents lies in the swept range (geometry-checked
        // above), so all must have been visited — else they sit on an index page
        // or past fileTail.
        if (visited != by_page.count()) return error.VerifyFailed; // extents on unallocated pages
    }

    const FreeRecidCtx = struct {
        store: *Self,
        max_recid: u64,
        set: *std.AutoHashMapUnmanaged(u64, void),
        err: ?DbError = null,
        fn onValue(self: *FreeRecidCtx, v: u64) DbError!void {
            const recid = v >> 1;
            if (recid < 1 or recid > self.max_recid) return error.VerifyFailed;
            const ivval = try self.store.rawIndexGet(recid);
            if (ivval != 0 and (!ivParityOk(ivval) or iv.capUnits(ivval) != iv.CAP_DELETED))
                return error.VerifyFailed;
            if ((try self.set.fetchPut(self.store.alloc, recid, {})) != null) return error.VerifyFailed;
        }
    };

    const ValueOffsetCtx = struct {
        store: *Self,
        size: u64,
        out: *std.ArrayListUnmanaged(Extent),
        free_sum: *i64,
        err: ?DbError = null,
        fn onValue(self: *ValueOffsetCtx, v: u64) DbError!void {
            try self.out.append(self.store.alloc, .{ .off = v << 3, .size = self.size });
            self.free_sum.* += @intCast(self.size);
        }
    };

    // ---------- full compact ----------

    fn compactSnapshot(self: *Self) DbError![]CompactEntry {
        var entries: std.ArrayListUnmanaged(CompactEntry) = .empty;
        errdefer {
            for (entries.items) |e| if (e.content) |c| self.alloc.free(c);
            entries.deinit(self.alloc);
        }
        const max = try self.maxRecid();
        var recid: u64 = 1;
        while (recid <= max) : (recid += 1) {
            const ivval = try self.rawIndexGet(recid);
            if (ivval == 0) continue;
            if (!ivParityOk(ivval)) return error.DataCorruption;
            const cap = iv.capUnits(ivval);
            if (cap == iv.CAP_DELETED) continue;
            if (cap == iv.CAP_NULL) {
                try entries.append(self.alloc, .{ .recid = recid, .prealloc = iv.isPrealloc(ivval), .cap_bytes = 0, .content = null });
            } else if (iv.isLinked(ivval)) {
                const content = try self.linkedGet(self.alloc, ivval);
                errdefer self.alloc.free(content); // do not leak on append OOM
                try entries.append(self.alloc, .{ .recid = recid, .prealloc = false, .cap_bytes = 0, .content = content });
            } else {
                const ou = try self.readUsed(ivval);
                const content = try self.alloc.alloc(u8, ou.used);
                errdefer self.alloc.free(content);
                try self.vol.getData(ou.off + 4, content);
                try entries.append(self.alloc, .{ .recid = recid, .prealloc = false, .cap_bytes = @as(usize, cap) * 16, .content = content });
            }
        }
        return entries.toOwnedSlice(self.alloc);
    }

    fn freeEntries(self: *Self, entries: []CompactEntry) void {
        for (entries) |e| if (e.content) |c| self.alloc.free(c);
        self.alloc.free(entries);
    }

    /// Rebuild densely from a pre-taken snapshot. Everything here is past the
    /// crash barrier, so any error poisons the store (caller's responsibility).
    fn compactInner(self: *Self, entries: []CompactEntry, max: u64) DbError!void {
        // 0) crash barrier: invalidate the on-disk checksum durably.
        try self.vol.putI32(O_HEAD_CHECKSUM, ~(try self.headChecksum()));
        try self.vol.sync();

        {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            try self.setDataTail(0);
            try self.setFileTail(PAGE_SIZE);
            try self.vol.putU64(O_FREE_RECID_STACK, parity.p4set(0));
            var u: u64 = 1;
            while (u <= MAX_CAP_UNITS) : (u += 1) try self.vol.putU64(masterLinkOffset(u), parity.p4set(0));
            try self.vol.putU64(ZERO_PAGE_LINK, parity.p16set(0));
            try self.vol.clear(ZERO_SLOTS_START, PAGE_SIZE);
            self.free_data_bytes.store(0, .monotonic);
            const empty_pages = try self.alloc.alloc(u64, 0);
            try self.index_pages.store(empty_pages);
            try self.setMaxRecid(max);
            if (max > 0) try self.ensureIndexCapacityLocked(max);
        }

        for (entries) |e| {
            if (e.content) |cnt| {
                if (needsLinked(cnt.len)) {
                    try self.writeNewLinked(e.recid, cnt);
                } else {
                    try self.writeNewData(e.recid, cnt, e.cap_bytes, 0);
                }
            } else {
                try self.indexSet(e.recid, iv.compose(iv.CAP_NULL, 0, if (e.prealloc) iv.FLAG_PREALLOC else 0));
            }
        }
        try self.rebuildFreeRecidsInner();
        try self.stampHeaderDurable();
        try self.vol.truncate(try self.fileTail());
    }

    // ---------- Store API ----------

    pub fn preallocate(self: *Self) DbError!u64 {
        mod.assertNotInAction("preallocate");
        try self.checkClosed();
        var c = try self.mutateEnter();
        defer c.unlock();
        const recid = blk: {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            break :blk try self.allocRecidLocked();
        };
        {
            var wg: SegWriteGuard = undefined;
            self.segs.write(recid, &wg);
            defer wg.unlock();
            try self.indexSet(recid, iv.compose(iv.CAP_NULL, 0, iv.FLAG_PREALLOC));
        }
        return recid;
    }

    pub fn put(self: *Self, comptime R: type, alloc: Allocator, value: R, ser: anytype) DbError!u64 {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        mod.assertNotInAction("put");
        try self.checkClosed();
        const buf = try self.serialize(R, value, ser);
        defer self.alloc.free(buf);
        const linked = needsLinked(buf.len);
        const cap_bytes = if (linked) 0 else try capBytesFor(4 + buf.len);
        var c = try self.mutateEnter();
        defer c.unlock();
        const recid = blk: {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            break :blk try self.allocRecidLocked();
        };
        {
            var wg: SegWriteGuard = undefined;
            self.segs.write(recid, &wg);
            defer wg.unlock();
            if (linked) {
                try self.writeNewLinked(recid, buf);
            } else {
                try self.writeNewData(recid, buf, cap_bytes, 0);
            }
        }
        return recid;
    }

    pub fn get(self: *Self, comptime R: type, alloc: Allocator, recid: u64, ser: anytype) DbError!?R {
        comptime mod.checkSer(R, @TypeOf(ser));
        mod.assertNotInAction("get");
        var c = try self.mutateEnter();
        defer c.unlock();
        var rg: SegReadGuard = undefined;
        self.segs.read(recid, &rg);
        defer rg.unlock();
        // serializer deserialize runs under the segment read lock: A3-guard it
        //
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const ivval = try self.indexGetChecked(recid);
        if (iv.capUnits(ivval) == iv.CAP_NULL) return null;
        if (iv.isLinked(ivval)) {
            const b = try self.linkedGet(self.alloc, ivval);
            defer self.alloc.free(b);
            var inp = DataInput2.init(b);
            return try ser.deserialize(alloc, &inp, b.len);
        }
        const ou = try self.readUsed(ivval);
        var bor: Volume.Borrow = undefined;
        try self.vol.borrowInto(ou.off + 4, ou.used, &bor);
        defer bor.deinit();
        var inp = DataInput2.init(bor.bytes);
        return try ser.deserialize(alloc, &inp, ou.used);
    }

    pub fn read(self: *Self, recid: u64, action: RecordRead) DbError!i64 {
        mod.assertNotInAction("read");
        var c = try self.mutateEnter();
        defer c.unlock();
        var rg: SegReadGuard = undefined;
        self.segs.read(recid, &rg);
        defer rg.unlock();
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const ivval = try self.indexGetChecked(recid);
        if (iv.capUnits(ivval) == iv.CAP_NULL) return action.callOnNull();
        if (iv.isLinked(ivval)) {
            const b = try self.linkedGet(self.alloc, ivval);
            defer self.alloc.free(b);
            var inp = DataInput2.init(b);
            return action.callOnBytes(&inp, b.len);
        }
        const ou = try self.readUsed(ivval);
        var bor: Volume.Borrow = undefined;
        try self.vol.borrowInto(ou.off + 4, ou.used, &bor);
        defer bor.deinit();
        var inp = DataInput2.init(bor.bytes);
        return action.callOnBytes(&inp, ou.used);
    }

    pub fn update(self: *Self, comptime R: type, alloc: Allocator, recid: u64, value: ?R, ser: anytype) DbError!void {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        return self.updateHeadroomOpt(R, recid, value, ser, 0);
    }

    fn updateHeadroomOpt(self: *Self, comptime R: type, recid: u64, value: ?R, ser: anytype, headroom: usize) DbError!void {
        mod.assertNotInAction("update");
        try self.checkClosed();
        const out: ?[]u8 = if (value) |v| try self.serialize(R, v, ser) else null;
        defer if (out) |o| self.alloc.free(o);
        if (out) |o| {
            if (!needsLinked(o.len)) _ = try capBytesFor(try plainNeed(o.len, headroom));
        }
        var c = try self.mutateEnter();
        defer c.unlock();
        var wg: SegWriteGuard = undefined;
        self.segs.write(recid, &wg);
        defer wg.unlock();
        const ivval = try self.indexGetChecked(recid);
        try self.updateLocked(recid, ivval, out, headroom);
    }

    /// segment write lock held; `ivval` is the current (checked) index value.
    fn updateLocked(self: *Self, recid: u64, ivval: u64, out: ?[]const u8, headroom: usize) DbError!void {
        const old_cap = iv.capUnits(ivval);
        const buf = out orelse {
            try self.releaseOldData(ivval);
            try self.indexSet(recid, iv.compose(iv.CAP_NULL, 0, 0));
            return;
        };
        if (needsLinked(buf.len)) {
            try self.releaseOldData(ivval);
            try self.writeNewLinked(recid, buf);
            return;
        }
        const need = try plainNeed(buf.len, headroom);
        if (!iv.isLinked(ivval) and old_cap != iv.CAP_NULL and need <= @as(u64, old_cap) * 16) {
            // in-place: validate the value-derived offset BEFORE writing (a
            // corrupt index must not clobber header/allocator words).
            const off = iv.offset(ivval);
            if (off < PAGE_SIZE or off & 15 != 0) return error.DataCorruption; // offset in header/misaligned
            try self.vol.checkRange(off, @as(u64, old_cap) * 16);
            try self.vol.putI32(off, @intCast(buf.len));
            try self.vol.putData(off + 4, buf);
            try self.indexSet(recid, iv.compose(old_cap, off, 0));
        } else {
            try self.releaseOldData(ivval);
            try self.writeNewData(recid, buf, try capBytesFor(need), 0);
        }
    }

    pub fn compareAndSwap(self: *Self, comptime R: type, alloc: Allocator, recid: u64, expect: ?R, new: ?R, ser: anytype) DbError!bool {
        comptime mod.checkSer(R, @TypeOf(ser));
        mod.assertNotInAction("compareAndSwap");
        try self.checkClosed();
        var c = try self.mutateEnter();
        defer c.unlock();
        var wg: SegWriteGuard = undefined;
        self.segs.write(recid, &wg);
        defer wg.unlock();
        // serializer callbacks (deserialize/equals/deinitElem and the rebuild's
        // serialize) run under the segment write lock: A3-guard them
        //
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const ivval = try self.indexGetChecked(recid);

        var eq: bool = undefined;
        if (iv.capUnits(ivval) == iv.CAP_NULL) {
            eq = expect == null;
        } else if (expect == null) {
            eq = false;
        } else {
            // deserialize current logical image under the lock (temp, caller alloc)
            const cur: R = if (iv.isLinked(ivval)) blk: {
                const b = try self.linkedGet(self.alloc, ivval);
                defer self.alloc.free(b);
                var inp = DataInput2.init(b);
                break :blk try ser.deserialize(alloc, &inp, b.len);
            } else blk: {
                const ou = try self.readUsed(ivval);
                var bor: Volume.Borrow = undefined;
                try self.vol.borrowInto(ou.off + 4, ou.used, &bor);
                defer bor.deinit();
                var inp = DataInput2.init(bor.bytes);
                break :blk try ser.deserialize(alloc, &inp, ou.used);
            };
            defer ser.deinitElem(alloc, cur);
            eq = ser.equals(cur, expect.?);
        }
        if (!eq) return false;

        const out: ?[]u8 = if (new) |v| try self.serialize(R, v, ser) else null;
        defer if (out) |o| self.alloc.free(o);
        try self.updateLocked(recid, ivval, out, 0);
        return true;
    }

    pub fn delete(self: *Self, recid: u64) DbError!void {
        mod.assertNotInAction("delete");
        try self.checkClosed();
        var c = try self.mutateEnter();
        defer c.unlock();
        var wg: SegWriteGuard = undefined;
        self.segs.write(recid, &wg);
        defer wg.unlock();
        const ivval = try self.indexGetChecked(recid);
        try self.releaseOldData(ivval);
        {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            try self.freeRecidLocked(recid);
        }
        try self.indexSet(recid, iv.compose(iv.CAP_DELETED, 0, 0));
    }

    pub fn commit(self: *Self) DbError!void {
        try self.checkClosed();
        self.commit_lock.lock();
        defer self.commit_lock.unlock();
        try self.checkClosed();
        try self.stampHeaderDurable();
    }

    pub fn compact(self: *Self) DbError!void {
        try self.checkClosed();
        self.commit_lock.lock();
        defer self.commit_lock.unlock();
        try self.checkClosed();
        // snapshot BEFORE the crash barrier: a failure here returns an ordinary
        // error WITHOUT poisoning/closing or touching the on-disk checksum.
        const entries = try self.compactSnapshot();
        defer self.freeEntries(entries);
        const max = try self.maxRecid();
        self.compactInner(entries, max) catch |e| {
            self.poisoned.store(true, .release);
            self.closed.store(true, .release);
            const hc = self.headChecksum() catch 0;
            self.vol.putI32(O_HEAD_CHECKSUM, ~hc) catch {};
            self.vol.sync() catch {};
            return e;
        };
    }

    pub fn close(self: *Self) DbError!void {
        if (self.closed.load(.acquire) and !self.poisoned.load(.acquire)) return;
        self.commit_lock.lock();
        defer self.commit_lock.unlock();
        if (self.closed.load(.acquire) and !self.poisoned.load(.acquire)) return;
        const stamp = !self.poisoned.load(.acquire);
        self.closed.store(true, .release);
        self.poisoned.store(false, .release);
        if (stamp) {
            const tail = try self.fileTail();
            try self.stampHeaderDurable();
            try self.vol.close(tail);
        } else {
            try self.vol.close(null);
        }
        const empty_pages = try self.alloc.alloc(u64, 0);
        try self.index_pages.store(empty_pages);
    }

    pub fn isClosed(self: *Self) bool {
        return self.closed.load(.acquire);
    }

    /// TEST ONLY: abandon the store WITHOUT stamping the header checksum durable
    /// — simulates a crash (process death) after an uncommitted mutation. The
    /// modified bytes are already in the shared page cache (MAP_SHARED); a reopen
    /// sees them against the stale checksum and must refuse. (Mirrors the Rust
    /// test's `std::mem::forget(store)`.)
    pub fn abandonForTest(self: *Self) void {
        self.closed.store(true, .release);
        self.freeAll();
    }

    pub fn isThreadSafe(self: *Self) bool {
        return self.thread_safe;
    }

    pub fn isTx(_: *Self) bool {
        return false;
    }

    /// lease registry accessor (the StoreLease capability).
    pub fn leaseTable(self: *Self) *LeaseTable {
        return &self.leases;
    }

    pub fn verify(self: *Self) DbError!void {
        try self.checkClosed();
        // Stop-the-world: verify reads whole-store geometry with raw accessors;
        // the exclusive commit lock is the correct oracle scope (excludes in-place
        // update/CAS/append that hold only a segment write lock).
        self.commit_lock.lock();
        defer self.commit_lock.unlock();
        try self.checkClosed();
        self.structural_lock.lock();
        defer self.structural_lock.unlock();
        self.verifyLocked() catch |e| return switch (e) {
            error.DataCorruption => error.VerifyFailed,
            else => e,
        };
    }

    pub fn getAllRecids(self: *Self, alloc: Allocator) DbError![]u64 {
        var c = try self.mutateEnter();
        defer c.unlock();
        const max = blk: {
            self.structural_lock.lock();
            defer self.structural_lock.unlock();
            break :blk try self.maxRecid();
        };
        var out: std.ArrayListUnmanaged(u64) = .empty;
        errdefer out.deinit(alloc);
        var recid: u64 = 1;
        while (recid <= max) : (recid += 1) {
            const ivval = blk: {
                var rg: SegReadGuard = undefined;
                self.segs.read(recid, &rg);
                defer rg.unlock();
                break :blk try self.rawIndexGet(recid);
            };
            if (ivval == 0) continue;
            // index slots lie outside the header checksum,
            // so a bit-flip survives a clean reopen. Validate parity + semantic
            // domain before classifying, else a corrupt slot could yield or omit a
            // recid instead of surfacing corruption.
            if (!ivParityOk(ivval)) return error.DataCorruption; // index slot parity broken
            if (!ivSemanticOk(ivval)) return error.DataCorruption; // capUnits/flags out of domain
            const cap = iv.capUnits(ivval);
            if (cap == iv.CAP_DELETED or iv.isPrealloc(ivval)) continue;
            try out.append(alloc, recid);
        }
        return out.toOwnedSlice(alloc);
    }

    pub fn getCurrentSize(self: *Self) u64 {
        self.structural_lock.lock();
        defer self.structural_lock.unlock();
        const ft: i64 = @intCast(self.fileTail() catch 0);
        const size = ft - self.free_data_bytes.load(.monotonic);
        return if (size < 0) 0 else @intCast(size);
    }

    // ---------- StoreDelta ----------

    pub fn append(self: *Self, recid: u64, data: []const u8) DbError!AppendResult {
        mod.assertNotInAction("append");
        try self.checkClosed();
        var c = try self.mutateEnter();
        defer c.unlock();
        var wg: SegWriteGuard = undefined;
        self.segs.write(recid, &wg);
        defer wg.unlock();
        const ivval = try self.indexGetChecked(recid);
        if (iv.isLinked(ivval)) return .refused;
        if (iv.capUnits(ivval) == iv.CAP_NULL) {
            if (needsLinked(data.len)) {
                try self.writeNewLinked(recid, data);
            } else {
                const cap_bytes = try capBytesFor(4 + data.len);
                try self.writeNewData(recid, data, cap_bytes, 0);
            }
            return .{ .new_size = data.len };
        }
        const ou = try self.readUsed(ivval);
        const cap_bytes = @as(usize, iv.capUnits(ivval)) * 16;
        const new_len = try tainted.checkedAdd(usize, 4 + ou.used, data.len);
        if (new_len > cap_bytes) return .refused;
        try self.vol.checkRange(ou.off, @intCast(new_len));
        try self.vol.putData(ou.off + 4 + ou.used, data);
        try self.vol.putI32(ou.off, @intCast(ou.used + data.len));
        return .{ .new_size = ou.used + data.len };
    }

    pub fn capacityRemaining(self: *Self, recid: u64) DbError!usize {
        mod.assertNotInAction("capacityRemaining");
        var c = try self.mutateEnter();
        defer c.unlock();
        var rg: SegReadGuard = undefined;
        self.segs.read(recid, &rg);
        defer rg.unlock();
        const ivval = try self.indexGetChecked(recid);
        if (iv.capUnits(ivval) == iv.CAP_NULL or iv.isLinked(ivval)) return 0;
        const ou = try self.readUsed(ivval);
        const cap = @as(usize, iv.capUnits(ivval)) * 16;
        return cap -| (4 + ou.used);
    }

    pub fn updateWithHeadroom(self: *Self, comptime R: type, alloc: Allocator, recid: u64, value: R, ser: anytype, headroom: usize) DbError!void {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        return self.updateHeadroomOpt(R, recid, value, ser, headroom);
    }

    // ---------- serialize helper ----------

    fn serialize(self: *Self, comptime R: type, value: R, ser: anytype) DbError![]u8 {
        var out = DataOutput2.init(self.alloc);
        defer out.deinit();
        try ser.serialize(&out, value);
        return out.toOwnedSlice();
    }
};

// ---------- free functions ----------

fn ivParityOk(ivval: u64) bool {
    return @popCount(ivval) & 1 == 1;
}

/// Semantic validation of a PARITY-OK persisted index value in its
/// semantic domain. An ordinary record's capUnits is in `[1, CAP_MAX_UNITS]`;
/// only the CAP_NULL / CAP_DELETED sentinels may lie outside that range, and a
/// sentinel must carry a zero offset and no LINKED flag (a linked/offset-bearing
/// sentinel is malformed). Rejecting `capUnits == 0` here is what keeps a
/// crafted-but-parity-valid slot from reaching `masterLinkOffset(0)` /
/// `releaseDataLocked(0, …)` and tripping a debug assert on a destructive path.
fn ivSemanticOk(ivval: u64) bool {
    const cap = iv.capUnits(ivval);
    if (cap == iv.CAP_NULL or cap == iv.CAP_DELETED)
        return iv.offset(ivval) == 0 and !iv.isLinked(ivval);
    return cap >= 1 and cap <= iv.CAP_MAX_UNITS;
}

fn extentLess(_: void, a: Extent, b: Extent) bool {
    return a.off < b.off;
}

/// The dataTail geometry invariant, shared by init_open and verify_locked. Valid
/// = 0 (no open page) OR 16-aligned, in the data area, strictly below fileTail,
/// and NOT page-aligned (a page-aligned nonzero tail is encoded as 0).
fn dataTailGeometryOk(data_tail: u64, file_tail: u64) bool {
    return data_tail == 0 or
        (data_tail % 16 == 0 and
            data_tail % PAGE_SIZE != 0 and
            data_tail >= PAGE_SIZE and
            data_tail < file_tail);
}

fn masterLinkOffset(cap_units: u64) u64 {
    std.debug.assert(cap_units >= 1 and cap_units <= MAX_CAP_UNITS);
    return O_FREE_DATA_STACKS + 8 * (cap_units - 1);
}

fn packLongSize(v: u64) u64 {
    var c: u64 = 1;
    var x = v;
    while (true) {
        x >>= 7;
        if (x == 0) break;
        c += 1;
    }
    return c;
}

fn needsLinked(content_len: usize) bool {
    return 4 + content_len > iv.MAX_CAPACITY;
}

fn checkSize(cap_bytes: usize) DbError!void {
    if (cap_bytes > iv.MAX_CAPACITY) return error.RecordTooLarge;
}

fn capBytesFor(need: usize) DbError!usize {
    const rounded = (std.math.add(usize, need, 15) catch return error.RecordTooLarge) & ~@as(usize, 15);
    try checkSize(rounded);
    return rounded;
}

/// Plain-record byte need = header(4) + content + headroom, checked wide.
fn plainNeed(content_len: usize, headroom: usize) DbError!usize {
    const a = std.math.add(usize, 4, content_len) catch return error.RecordTooLarge;
    return std.math.add(usize, a, headroom) catch return error.RecordTooLarge;
}

// ------------------------------------------------------------------- tests

test {
    std.testing.refAllDecls(@This());
}
