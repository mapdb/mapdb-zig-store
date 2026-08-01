//! The WAL's **multi-file namespace** — `<base>.wal.<16 lowercase hex digits>`,
//! the store lock, and every operation that changes which files exist: create,
//! seal, unlink, directory fsync.
//!
//! Port of `mapdb-rust-store/src/store/wal_segments.rs`, itself a port of Java
//! `WalSegmentSet` (format v3). It owns the **namespace** (N) and **segment
//! header** (H) decision tables and the writer obligations that are about files
//! rather than bytes (W2, W5, W6, and the force-flavour rule); sections, entries
//! and the recovery state machine (S/K/R) live in `wal_recover.zig`. The split is
//! the Java one and is deliberate: the expensive part of the format to port is
//! this state machine, not the codec.
//!
//! ```text
//! name    := <base> ".wal." <16 lowercase hex digits of segmentSeq>
//! header  := magic "MDBS.WAL"(8) | version i32 = 3 | flags i32 = 0
//!          | segmentSeq i64 | firstLsn i64 | headerCrc i32        // 36 bytes
//! ```
//!
//! All integers big-endian; `headerCrc` is zlib CRC-32 over header bytes
//! `[0, 32)`. The first segment of a store has `segmentSeq = 1`, so `0` is free
//! to mean "no clean mark". Sixteen fixed hex digits make lexicographic order
//! equal numeric order in every port's directory listing; the *name* is the
//! enumeration key and the *header* is the authority, which is what catches a
//! copied or renamed segment (N5/H7).
//!
//! # The legacy boundary (D1)
//!
//! The ports' v1 opener took the WAL FILE path, so after the v3 cutover the same
//! call site hands what is now a BASE. Three pre-existing artifacts therefore
//! refuse the open rather than being ignored, and none of them is ever deleted:
//! a regular file at `<base>.wal` (Java's own N6 row), a regular file at
//! `<base>` itself, and a `<base>.ckpt` left by v1's rename-checkpoint — which
//! after a v1 crash may be the only recoverable copy. Silently starting a fresh
//! segment set beside any of them is the one outcome the format break exists to
//! prevent.
//!
//! # Zig-specific notes
//!
//! - **Diagnostics.** Zig errors carry no payload, so every refusal writes a
//!   STATIC reason string plus the offending sequence number into
//!   [`WalSegmentSet.reason`] / `reason_seq` before returning. Rust formats the
//!   same text into the error itself. The reason is a diagnostic, never a key:
//!   nothing branches on it.
//! - **No destructors.** Rust leans on `Drop` to release the lock on every early
//!   return out of `open`. Every fallible step here is covered by an `errdefer`
//!   that runs the same release, in the same order.
//! - **Allocation failure is operational, never corruption** (design §6 risk 14):
//!   `error.OutOfMemory` propagates and the ordinary failed-open cleanup runs. It
//!   is never held as a verdict and never classified as a torn tail.
//! - Linux-scoped, like the rest of this store: the lock is an OFD record lock
//!   and the directory fsync needs a real directory fd.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const wal_io = @import("wal_io.zig");
const WalIo = wal_io.WalIo;
const walIoEvent = wal_io.walIoEvent;

const Crc32 = std.hash.crc.Crc32;

comptime {
    // The OFD lock command number and the directory-fsync discipline below are
    // Linux contracts. A port to another platform must re-derive both rather
    // than inherit a constant that happens to compile.
    std.debug.assert(builtin.os.tag == .linux);
}

/// magic(8) + version(4) + flags(4) + segmentSeq(8) + firstLsn(8) + headerCrc(4).
pub const SEG_HDR: u64 = 36;
/// Bytes of the segment header covered by `headerCrc`.
pub const SEG_HDR_CRC_LEN: usize = 32;
pub const MAGIC: [8]u8 = "MDBS.WAL".*;
/// v3 adds `firstLsn` to the header and a second `i64` to the `'K'` body.
///
/// Those two fields exist to **delete inference**. v2 asked recovery to work out
/// whether a missing segment was authorized, and where the retained log
/// legitimately began, from circumstantial evidence — LSN density, the position
/// of the mark, the tag of the first retained section. Six defects lived in that
/// reasoning across four revisions, two of them permanent bricks and two silent
/// data loss. Recording the two facts directly turns every one of those
/// questions into an equality between two numbers a conforming writer wrote
/// down.
pub const FORMAT_VERSION: i32 = 3;
/// Sequence number of a store's first segment; 0 is reserved for "no clean mark".
pub const FIRST_SEQ: i64 = 1;

/// The name suffix that turns a base into a segment prefix.
const NAME_INFIX = ".wal.";
/// Exactly sixteen lowercase hex digits follow [`NAME_INFIX`].
const HEX_DIGITS: usize = 16;

inline fn crc32(bytes: []const u8) u32 {
    return Crc32.hash(bytes);
}

inline fn getI32Be(b: []const u8, off: usize) i32 {
    return std.mem.readInt(i32, b[off..][0..4], .big);
}

inline fn getI64Be(b: []const u8, off: usize) i64 {
    return std.mem.readInt(i64, b[off..][0..8], .big);
}

// ------------------------------------------------------------------- segment

/// One segment file. `valid_end` and the LSN fields are pass-1 results filled in
/// by the recovery scanner; everything else is namespace state owned by this
/// module.
pub const Segment = struct {
    seq: i64,
    /// Owned; freed by [`deinit`](Segment.deinit).
    path: []u8,
    read_only: bool,
    /// Opened ON DEMAND and released as soon as a recovery pass is done with
    /// this segment.
    ///
    /// Holding one handle per segment for the store's lifetime is what a
    /// straightforward implementation does, and it does not scale: nothing reads
    /// a segment after recovery — the record map lives in the memory-backed
    /// inner store and only the ACTIVE segment is ever appended to — while the
    /// log is allowed to reach roughly twice the live data size, so a large
    /// store means thousands of open descriptors against a default `ulimit -n`
    /// of 1024. A legitimate store would fail to open with `EMFILE`, and an
    /// attacker-supplied directory of valid header-only segments could force it
    /// deliberately.
    file: ?std.fs.File = null,
    /// The 36 header bytes, verbatim — used as an identity string in the section
    /// CRC domain.
    header: [@as(usize, SEG_HDR)]u8,
    file_len: u64,
    /// End offset of the valid section prefix (pass 1). Never below [`SEG_HDR`].
    valid_end: u64 = SEG_HDR,
    /// LSNs of the first and last accepted sections, or 0 when the segment holds
    /// none. **0 doubles as "none seen"**, and that ambiguity is frozen
    /// reference behaviour, not an oversight — see the Java pin tests
    /// (`StoreWALFrozenEdgeTest`).
    first_lsn: i64 = 0,
    last_lsn: i64 = 0,
    /// A corruption verdict found in this segment, HELD until R4 decides it is
    /// relevant. A static reason string; `null` means no verdict.
    held: ?[]const u8 = null,

    fn init(seq: i64, path: []u8, read_only: bool, header: [@as(usize, SEG_HDR)]u8, file_len: u64) Segment {
        return .{
            .seq = seq,
            .path = path,
            .read_only = read_only,
            .header = header,
            .file_len = file_len,
        };
    }

    /// Releases the handle and frees the owned path. The segment is dead after
    /// this; the set calls it when a segment leaves the live list.
    pub fn deinit(self: *Segment, alloc: Allocator) void {
        self.release();
        alloc.free(self.path);
        self.path = &.{};
    }

    /// Opens this segment's file if it does not already hold one. Idempotent.
    pub fn ensureOpen(self: *Segment) DbError!void {
        if (self.file != null) return;
        const mode: std.fs.File.OpenMode = if (self.read_only) .read_only else .read_write;
        self.file = std.fs.cwd().openFile(self.path, .{ .mode = mode }) catch return error.Io;
    }

    /// The handle, or `null` when [`ensureOpen`](Segment.ensureOpen) has not run
    /// since the last [`release`](Segment.release).
    ///
    /// BORROWED. Rust's borrow checker makes that a compile error to violate and
    /// Zig cannot, so it is a rule instead: a caller reads and writes through the
    /// returned handle and never closes it. Closing is
    /// [`release`](Segment.release)'s job, because it is also what clears the
    /// field this returns a copy of.
    pub fn handle(self: *const Segment) ?std.fs.File {
        return self.file;
    }

    /// Closes the handle if one is held; the segment stays usable and reopens on
    /// demand. Called as soon as a recovery pass finishes with a segment, which
    /// is what bounds the descriptor count to O(1) instead of O(segments).
    /// Nothing is written through these handles without a preceding force, so a
    /// lost close never loses data.
    pub fn release(self: *Segment) void {
        if (self.file) |f| f.close();
        self.file = null;
    }

    /// Feeds `crc` this section's **domain separator**: the 36 header bytes
    /// verbatim followed by the big-endian section offset. An ordinary CRC-32
    /// over a prefix — NOT a preloaded register, which would force every port to
    /// reimplement a private convention.
    ///
    /// Binding the segment identity rejects a section byte-copied between
    /// segments; binding the offset rejects one copied to a different offset in
    /// the same segment. The domain intentionally includes the header's own
    /// `headerCrc` field: the 36 bytes are an identity string, not a re-parsed
    /// structure. It therefore also covers `firstLsn`, so a segment whose stated
    /// start is edited invalidates every section CRC in it.
    ///
    /// (Java's javadoc says `[0..28)`; the Java CODE, the Rust port, this port
    /// and the byte-level test kit all use all 36 bytes. 36 is authoritative.)
    pub fn crcDomain(self: *const Segment, crc: *Crc32, section_offset: u64) void {
        crcDomainOf(crc, &self.header, section_offset);
    }

    /// **The LSN this segment's first section holds** — `nextLsn` at the moment
    /// the writer created it, recorded in the header so recovery never has to
    /// infer it. A segment that holds no section still states where its first one
    /// would have gone, which is exactly what separates "this segment was always
    /// empty" from "its sections vanished".
    pub fn headerFirstLsn(self: *const Segment) i64 {
        return getI64Be(&self.header, 24);
    }

    /// True while this segment holds no accepted section (H8).
    pub fn empty(self: *const Segment) bool {
        return self.valid_end == SEG_HDR;
    }
};

/// One enumerated header's verdict. Java encodes the same three-way answer as
/// `null` / plain string / `"!"`-prefixed string; Rust uses an enum with a
/// `String`, and Zig an enum with a STATIC reason (see the module note on
/// diagnostics).
const HeaderVerdict = struct {
    kind: enum {
        /// Valid v3 header (H8 included: a header-only segment is legitimate).
        ok,
        /// H1-H4: the *torn-create* shapes. Residue when this is the highest
        /// name, corruption anywhere below it.
        torn,
        /// H5-H7/H9: a CRC-valid header carrying wrong content — a writer defect
        /// or a copied file, never a torn create. Corruption wherever it appears.
        corrupt,
    },
    reason: []const u8 = "",
};

// --------------------------------------------------------------- the segment set

pub const WalSegmentSet = struct {
    alloc: Allocator,
    /// The store path as opened, absolutized and then used verbatim — never
    /// canonicalized and never reduced to a basename, or two opens by different
    /// paths would disagree on the namespace. Mirrors Java's `getAbsoluteFile()`.
    /// Owned.
    base: []u8,
    /// `dirname(base)`, a slice INTO `base` — no separate allocation, and it
    /// stays valid because `base` is owned and never reallocated.
    dir: []const u8,
    /// `<base file name>.wal.` as raw bytes. A Unix path is a byte string, and
    /// requiring UTF-8 here would make a perfectly legal namespace unopenable in
    /// this port alone (Java derives the prefix from `File.getName()` with no
    /// such requirement, and defines acceptance by an ASCII suffix and file type
    /// — `WalSegmentSet.java:199-207, 279-311`). Owned.
    prefix: []u8,
    read_only: bool,
    /// Ascending by sequence number.
    segments: std.ArrayListUnmanaged(Segment) = .empty,
    /// W6: one above the highest sequence number seen in ANY enumerated name,
    /// orphans included.
    next_seq: i64 = FIRST_SEQ,
    /// Total `file_len` of every segment EXCEPT the highest, which is the only
    /// one that grows. Maintained at the two points that change which segments
    /// exist, so [`logBytes`](WalSegmentSet.logBytes) is O(1): it is consulted on
    /// every commit (the cleaning trigger), under the WAL write lock, and summing
    /// the list there is proportional to the number of committed sections at the
    /// minimum segment size.
    sealed_bytes: u64 = 0,
    /// The store lock. Held for as long as this handle is open — closing the file
    /// releases the OFD lock taken on it. `null` only in the read-only-medium
    /// case (see [`takeStoreLock`](WalSegmentSet.takeStoreLock)).
    lock: ?std.fs.File = null,
    /// The in-process half of the same lock; released after `lock`.
    claim: ?ProcessClaim = null,
    /// True once [`close`](WalSegmentSet.close) has run: the namespace mutations
    /// must not run without the lock this handle no longer holds.
    closed: bool = false,
    /// The durability seam. Borrowed for the life of the set — per set rather
    /// than per process, see [`WalIo`](wal_io.WalIo).
    io: ?*const WalIo = null,
    /// Diagnostic side channel: a STATIC reason string written immediately before
    /// a refusal, and the sequence number it is about (0 when none). Never
    /// load-bearing for control flow.
    reason: []const u8 = "",
    reason_seq: i64 = 0,
    /// Durability observation, per set. Java exposes the same points through its
    /// event seam; a byte comparison of a SUCCESSFUL create cannot tell a missing
    /// fsync from a present one, and the no-op `unlinkThrough` must be shown not
    /// to fsync at all. Kept unconditionally rather than behind a test-only
    /// switch — two counters cost nothing and a conditional field would make the
    /// struct layout differ between the tested and the shipped build.
    dir_fsyncs: u64 = 0,
    segment_syncs: u64 = 0,

    const Self = @This();

    /// Opens the namespace: takes the store lock, enumerates and classifies
    /// (R0/R1), and removes create-crash residue (R2). Leaves the surviving
    /// segments in the set, ascending, with no file handles held; section-level
    /// recovery is the caller's job.
    pub fn open(alloc: Allocator, base: []const u8, read_only: bool) DbError!Self {
        return openWithIo(alloc, base, read_only, null);
    }

    /// [`open`](WalSegmentSet.open) with a durability seam installed for the
    /// whole lifetime of the set, including the create and unlink this open
    /// itself performs (R2's residue removal).
    pub fn openWithIo(
        alloc: Allocator,
        base: []const u8,
        read_only: bool,
        io: ?*const WalIo,
    ) DbError!Self {
        const abs: []u8 = if (std.fs.path.isAbsolute(base))
            (alloc.dupe(u8, base) catch return error.OutOfMemory)
        else abs: {
            const cwd = std.process.getCwdAlloc(alloc) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Io,
            };
            defer alloc.free(cwd);
            break :abs std.fs.path.join(alloc, &.{ cwd, base }) catch return error.OutOfMemory;
        };
        errdefer alloc.free(abs);

        // A base with no file-name component names no store: `dirname` would own
        // the whole path and the prefix would be empty, so every name in the
        // directory would match.
        const name = std.fs.path.basename(abs);
        if (name.len == 0) return error.WrongConfiguration;
        const dir = std.fs.path.dirname(abs) orelse ".";

        const prefix = std.mem.concat(alloc, u8, &.{ name, NAME_INFIX }) catch
            return error.OutOfMemory;
        errdefer alloc.free(prefix);

        var set = Self{
            .alloc = alloc,
            .base = abs,
            .dir = dir,
            .prefix = prefix,
            .read_only = read_only,
            .io = io,
        };
        // Every early return from here releases the store lock and everything
        // else the set has taken — Java's `finally { closeQuietly() }` and Rust's
        // `Drop`. NOT `set.deinit()`: `base` and `prefix` are already covered by
        // the two errdefers above, and running both would free them twice.
        errdefer {
            set.close();
            set.segments.deinit(alloc);
        }

        try set.takeStoreLock();
        try set.refuseLegacyArtifacts();

        var found = try set.enumerate();
        defer found.deinit(alloc);
        try set.classify(found.items);
        return set;
    }

    /// D1: the legacy boundary. All three rows REFUSE, delete nothing, and fire
    /// before any v3 segment is created. Regular files only, the same discipline
    /// N4 applies: a DIRECTORY at one of these names is not a legacy artifact —
    /// except `.ckpt`, which refuses on EXISTENCE whatever the entry is.
    ///
    /// N6 is Java's own row; the other two are the ports' upgrade-safety boundary
    /// and have no Java counterpart, because Java's base has never named a file.
    /// A v1 caller passed the WAL FILE path, so the same call site now passes a
    /// BASE — and N6 alone would look at `<arg>.wal`, miss the old log sitting at
    /// `<arg>`, and open a fresh empty store beside the user's only durable copy.
    fn refuseLegacyArtifacts(self: *Self) DbError!void {
        const Row = struct { suffix: []const u8, reason: []const u8, any_kind: bool };
        const rows = [_]Row{
            .{
                .suffix = ".wal",
                .reason = "v1 single-file WAL present at <base>.wal: no migration to v3 — " ++
                    "open it with the release that wrote it and copy the data across, or move it aside",
                .any_kind = false,
            },
            .{
                .suffix = "",
                .reason = "regular file at the WAL base path (the v3 opener takes a base, not a log file): " ++
                    "no migration to v3 — open it with the release that wrote it and copy the data " ++
                    "across, or move it aside",
                .any_kind = false,
            },
            // `.ckpt` refuses on EXISTENCE, whatever the entry is — the one row of
            // the three that is not a regular-file test. D1 makes it the sentinel
            // precisely because it may be the only recoverable copy after a v1
            // crash, and "there is something at that name and I cannot tell what"
            // is not a reason to create a fresh store beside it. The other two
            // rows stay regular-file: a directory at `<base>` or `<base>.wal` is
            // not a legacy log, and refusing there would make ordinary directory
            // layouts unopenable.
            .{
                .suffix = ".ckpt",
                .reason = "v1 checkpoint temp present at <base>.ckpt, possibly the only recoverable copy " ++
                    "after a v1 crash: no migration to v3 — open it with the release that wrote it and " ++
                    "copy the data across, or move it aside",
                .any_kind = true,
            },
        };
        for (rows) |row| {
            const path = try self.withSuffix(row.suffix);
            defer self.alloc.free(path);
            const present = if (row.any_kind) pathExistsNoFollow(path) else isRegularFile(path);
            if (present) {
                self.note(row.reason, 0);
                return error.DataCorruption;
            }
        }
    }

    /// §3.1: exactly one process may run open, recovery or writing at a time.
    /// Recovery unlinks, truncates and rotates, and two concurrent opens would
    /// also pick the same next sequence number. v1 took no lock; this is new.
    ///
    /// The lock has **two halves**, because Java's has two halves and neither one
    /// alone reproduces it:
    ///
    /// 1. An **OFD record lock** (`fcntl(F_OFD_SETLK)`) on `<base>.lock`.
    ///    Not `flock`: BSD locks and POSIX record locks are independent lock
    ///    classes on Linux, so a `flock` here would not exclude — at all — a Java
    ///    process holding the same store through `FileChannel.tryLock`, which is
    ///    a record lock (`WalSegmentSet.java:267-274`). Uniformity across
    ///    implementations is the ruling this port exists to serve, and a lock that
    ///    only excludes its own language is not one. Measured against a live JVM
    ///    holder rather than assumed: `flock` acquires straight through Java's
    ///    lock, `F_OFD_SETLK` is refused by it and acquires as soon as Java
    ///    releases. OFD (rather than plain `F_SETLK`) because ownership is the
    ///    open file description, not the process: a second open in one process is
    ///    refused instead of silently upgrading the first one's lock, and closing
    ///    any other descriptor on the file cannot drop this lock.
    /// 2. A **process-local claim** keyed by the lock file's `(device, inode)`.
    ///    Java holds its locks in a JVM-wide table and refuses ANY overlapping
    ///    second lock in the same JVM — `OverlappingFileLockException` does not
    ///    consider lock MODE, so even two read-only opens of one store are refused
    ///    (verified against the JVM, not merely read off the javadoc). No kernel
    ///    lock can express that: two OFD read locks are compatible by
    ///    construction, which is the entire point of a read lock. So the port
    ///    keeps the table Java keeps.
    ///
    /// The two halves are released in the reverse order they are taken (the file,
    /// then the claim), so no window exists in which this process has forgotten
    /// the store while the kernel still holds its lock.
    fn takeStoreLock(self: *Self) DbError!void {
        const lock_path = try self.withSuffix(".lock");
        defer self.alloc.free(lock_path);

        const handle: std.fs.File = if (self.read_only) ro: {
            // §3.1 is TWO-SIDED: a reader must be rejected while a writer holds
            // the exclusive lock, AND a writer must be rejected while a reader
            // holds a shared one. So CREATE the lock file when the directory
            // allows it, even though this open will not modify the store.
            break :ro std.fs.cwd().createFile(lock_path, .{ .read = true, .truncate = false }) catch {
                // Going lockless is the one outcome that reintroduces the race,
                // so it needs a POSITIVE reason — not merely "the create failed".
                // An error here can be a transient I/O fault, a quota, or an ACL
                // on this one pathname, none of which imply that no writer can
                // create the file and lock it exclusively.
                // A FOLLOWING existence test, unlike D1's `.ckpt` sentinel. The
                // question here is "can this path be opened", and a dangling
                // symlink answers no — Rust asks `Path::exists()` and Java
                // `File.exists()`, both of which follow, so a dangling link falls
                // through to the writable-directory rung and fails closed as
                // inconclusive contention. Answering "present" for it instead
                // would try an open that cannot succeed and report the resulting
                // `Io`, which tells the caller the wrong thing about the store.
                if (pathExistsFollowing(lock_path)) {
                    // Ambiguity resolved: the file is there, so a shared lock is
                    // still attainable on a read-only handle. This is not a
                    // fallback to lockless at all.
                    break :ro std.fs.cwd().openFile(lock_path, .{ .mode = .read_only }) catch
                        return error.Io;
                } else if (!isWritableDir(self.dir)) {
                    // Java's read-only-medium branch, and Java's exact heuristic:
                    // `access(W_OK)` answers for THIS process's credentials. It is
                    // evidence that no writer can create the lock file, not proof
                    // — another uid, or root, still can. The behaviour is frozen
                    // by the reference (see `WalSegmentSet.java:248-255`, whose
                    // comment claims more than the check delivers); tightening it
                    // to a real `ST_RDONLY` mount test would change the set of
                    // stores that open, so it is an owner decision, not a port
                    // one.
                    return;
                } else {
                    self.note(
                        "cannot take a shared store lock on <base>.lock and the directory is " ++
                            "writable, so a writer may be running",
                        0,
                    );
                    return error.Locked;
                }
            };
        } else std.fs.cwd().createFile(lock_path, .{ .read = true, .truncate = false }) catch
            return error.Io;
        errdefer handle.close();

        // Identity of the LOCK FILE, not of the path used to reach it: two opens
        // naming the same store through different paths (a symlinked directory, a
        // bind mount, `./db` vs `db`) must collide, and Java's lock table is
        // likewise keyed by file identity rather than by pathname.
        const st = std.posix.fstat(handle.handle) catch return error.Io;
        var claim = ProcessClaim.take(.{ st.dev, st.ino }) catch return error.OutOfMemory;
        if (claim == null) {
            self.note("WAL store is already open in this process", 0);
            return error.Locked;
        }
        // Released on every error path below.
        errdefer claim.?.release();

        if (!try tryOfdLock(handle, !self.read_only)) {
            self.note("WAL store is locked by another process", 0);
            return error.Locked;
        }
        self.lock = handle;
        self.claim = claim;
    }

    // ---------- R0: enumerate ----------

    /// R0/N4. Collects every **regular file** whose name is exactly the prefix
    /// followed by 16 lowercase hex digits with a non-negative `i64` value.
    /// Directories, symlinks, uppercase hex, wrong lengths and the `.lock` file
    /// are not segments and are ignored — ignored, not rejected, because a store
    /// directory is allowed to contain other things. Sequence GAPS are legal:
    /// integrity comes from the recorded LSNs, not from contiguity.
    ///
    /// Java's `dir.list()` answers null for an unreadable/absent directory and
    /// the constructor treats that as "no segments"; a fresh store then creates
    /// its first segment, which is where a genuinely broken directory surfaces as
    /// the I/O error it is. Open-time leniency only — see
    /// [`enumerateChecked`](WalSegmentSet.enumerateChecked) for the callers that
    /// must not guess.
    ///
    /// The leniency is scoped to the I/O answer and to nothing else. Rust writes
    /// this as `enumerate_checked().unwrap_or_default()`, which is safe THERE
    /// only because `Vec::push` cannot report an allocation failure: every error
    /// that reaches its `unwrap_or_default` really is the directory answer. Zig's
    /// append can, so the same catch-all would turn "I ran out of memory
    /// half-way through the listing" into "this namespace has no segments" — and
    /// the caller would then create segment 1 over a store that already has one.
    /// `OutOfMemory` is operational (design §6 risk 14) and propagates.
    fn enumerate(self: *Self) DbError!std.ArrayListUnmanaged(i64) {
        return self.enumerateChecked() catch |e| switch (e) {
            error.Io => .empty,
            else => e,
        };
    }

    /// [`enumerate`](WalSegmentSet.enumerate) without the leniency: an unreadable
    /// directory or a failed directory entry is an ERROR, not an empty namespace.
    ///
    /// D2's delete needs this and open does not. Deleting is the one caller for
    /// which "I could not read the directory" and "there is nothing here" have
    /// opposite meanings: guessing the second reports a clean removal of files
    /// that are still on disk, having already unlinked the lock and cleared the
    /// in-memory list.
    fn enumerateChecked(self: *Self) DbError!std.ArrayListUnmanaged(i64) {
        var found: std.ArrayListUnmanaged(i64) = .empty;
        errdefer found.deinit(self.alloc);

        var dir = std.fs.cwd().openDir(self.dir, .{ .iterate = true }) catch return error.Io;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch return error.Io) |entry| {
            // Matched as BYTES: a name is not required to be UTF-8 to be a
            // segment, and neither is the base path it hangs off.
            if (!std.mem.startsWith(u8, entry.name, self.prefix)) continue;
            const hex = entry.name[self.prefix.len..];
            if (hex.len != HEX_DIGITS) continue;
            // Uppercase hex does not match, and enumeration is case-SENSITIVE
            // even on a case-insensitive filesystem; a value >= 2^63 (negative as
            // i64) is not a segment.
            if (!allLowerHex(hex)) continue;
            const raw = std.fmt.parseUnsigned(u64, hex, 16) catch continue;
            if (raw > @as(u64, std.math.maxInt(i64))) continue;
            const seq: i64 = @intCast(raw);
            // Symlinks are NOT followed, so a symlink to a valid segment is not a
            // segment.
            //
            // The FAILURE here is not "not a segment": this name has already
            // matched the exact segment grammar, so it is one of ours and we
            // simply could not tell what it is. Open may guess (Java's
            // `Files.isRegularFile` guesses the same way), but D2's delete may not
            // — guessing "not a file" there leaves a segment on disk under an
            // owned name while the caller is told the namespace is gone.
            switch (entry.kind) {
                .file => {},
                // The kernel declined to answer from the directory entry (some
                // filesystems always do). Ask explicitly rather than guess.
                .unknown => {
                    const st = std.posix.fstatat(
                        dir.fd,
                        entry.name,
                        std.posix.AT.SYMLINK_NOFOLLOW,
                    ) catch return error.Io;
                    if (!std.posix.S.ISREG(st.mode)) continue;
                },
                else => continue,
            }
            found.append(self.alloc, seq) catch return error.OutOfMemory;
        }
        std.mem.sort(i64, found.items, {}, std.sort.asc(i64));
        return found;
    }

    /// `<dir>/<prefix><seq:016x>` — the one place the name grammar is produced.
    /// Owned; caller frees.
    ///
    /// Built from `dir` and `prefix` rather than by appending to `base`, which
    /// would be the same string in every ordinary case and a DIFFERENT one when
    /// the caller's base carries a trailing separator: `"/a/b/"` names segments
    /// `/a/b.wal.…`, because `prefix` comes from the base's file-name component.
    /// Rust composes it the same way, and the two ports have to agree on which
    /// files a namespace owns.
    pub fn segmentFile(self: *const Self, seq: i64) DbError![]u8 {
        const sep: []const u8 = if (std.mem.endsWith(u8, self.dir, "/")) "" else "/";
        // `@bitCast`, not `@intCast`: this is also the diagnostic path, and a
        // diagnostic must never panic on a value that reached it by mistake.
        return std.fmt.allocPrint(
            self.alloc,
            "{s}{s}{s}{x:0>16}",
            .{ self.dir, sep, self.prefix, @as(u64, @bitCast(seq)) },
        ) catch error.OutOfMemory;
    }

    // ---------- R1/R2: classify, remove residue ----------

    /// R1 then R2. Applies table H to every enumerated name, unlinks create-crash
    /// residue, and records the maximum sequence over ALL names — **including the
    /// residue it is about to remove** (W6), so a stale directory entry can never
    /// alias a segment a later create reuses.
    ///
    /// The asymmetry in table H is the whole point: a torn create produces an
    /// invalid `headerCrc` with overwhelming probability, so an invalid header on
    /// the **highest** name is an ordinary crash artifact, while the same bytes
    /// anywhere else are corruption — something above it exists, so its creation
    /// completed once.
    fn classify(self: *Self, found: []const i64) DbError!void {
        var max_observed: i64 = 0;
        for (found) |s| max_observed = @max(max_observed, s);
        // A namespace that has run out of sequence numbers is exhausted, not
        // damaged: every byte on disk is intact and readable, there is simply no
        // name left to create. `StoreFull` is the capacity ceiling; Java throws a
        // plain `DBException` here (`WalSegmentSet.java:329-334`).
        self.next_seq = std.math.add(i64, max_observed, 1) catch return error.StoreFull;

        const highest: ?i64 = if (found.len == 0) null else found[found.len - 1];
        var residue: std.ArrayListUnmanaged(i64) = .empty;
        defer residue.deinit(self.alloc);

        for (found) |seq| {
            // Sequence 0 is RESERVED for "no clean mark", so no conforming writer
            // can ever create it: FIRST_SEQ is 1 and next_seq only increases.
            // Rejected here, at R1, rather than left to fall through — R4 would
            // refuse it today only as a side effect of its retained set coming out
            // empty, which is an accident, not a rule.
            if (seq == 0) {
                self.note("sequence 0 is reserved for \"no clean mark\" and is never a segment", 0);
                return error.DataCorruption;
            }
            const path = try self.segmentFile(seq);
            var keep_path = false;
            defer if (!keep_path) self.alloc.free(path);

            const mode: std.fs.File.OpenMode = if (self.read_only) .read_only else .read_write;
            const file = std.fs.cwd().openFile(path, .{ .mode = mode }) catch return error.Io;
            defer file.close();
            const len = file.getEndPos() catch return error.Io;
            var hdr: [@as(usize, SEG_HDR)]u8 = undefined;
            const verdict = try readHeader(file, len, &hdr, seq);
            switch (verdict.kind) {
                // The handle is NOT retained: a recovery pass reopens it on demand
                // and releases it again, so the descriptor count stays O(1) in the
                // segment count.
                .ok => {
                    self.segments.append(
                        self.alloc,
                        Segment.init(seq, path, self.read_only, hdr, len),
                    ) catch return error.OutOfMemory;
                    keep_path = true;
                },
                .corrupt => {
                    self.note(verdict.reason, seq);
                    return error.DataCorruption;
                },
                .torn => {
                    if (highest != null and highest.? == seq) {
                        // H1-H4 on the highest name: the create crashed. A
                        // read-only open excludes it from the set but keeps the
                        // file — the next writable open removes it.
                        residue.append(self.alloc, seq) catch return error.OutOfMemory;
                    } else {
                        // Not the highest segment, so its create completed.
                        self.note(verdict.reason, seq);
                        return error.DataCorruption;
                    }
                },
            }
        }
        if (!self.read_only and residue.items.len > 0) {
            for (residue.items) |seq| {
                const path = try self.segmentFile(seq);
                defer self.alloc.free(path);
                // R2's unlink is a reported operation, exactly like W5's. Java
                // emits it (`WalSegmentSet.java:376-381`); Rust does not, which
                // is a gap against the frozen reference rather than a decision —
                // the seam post-dates its A0 and nothing went back to fill this
                // one in. Without the event, the one namespace mutation an OPEN
                // performs is neither observable nor fault-injectable.
                try walIoEvent(self.io, .unlink, seq, 0, 0, 0);
                try removeIfExists(path);
            }
            try self.fsyncDir();
        }
        self.recomputeSealedBytes();
    }

    // ---------- the namespace mutations ----------

    /// W2: `create → write header → force(true) → fsync the directory`, and only
    /// then may a section be appended. Without the directory fsync the whole
    /// segment can vanish on a crash, taking acknowledged commits with it; without
    /// the size-persisting force the header itself can be lost. Returns the new
    /// active segment, appended to the set.
    pub fn createSegment(self: *Self, first_lsn: i64) DbError!*Segment {
        if (self.closed) return error.StoreClosed;
        // Java throws a plain `DBException` for all three of these; the ports pick
        // the nearest non-corruption variants, because NOTHING on disk is damaged
        // in any of them and a caller that treats the store as corrupt would be
        // reacting to its own bug. (`WalSegmentSet.java:435-441`.)
        if (self.read_only) return error.ReadOnly;
        if (first_lsn <= 0) {
            self.note("segment firstLsn must be positive", 0);
            return error.WrongConfiguration;
        }
        const seq = self.next_seq;
        // The name is burned here, BEFORE any I/O (W6) — a failed create must
        // never hand its sequence number to the next one. On overflow Java wraps
        // `nextSeq` negative and only then throws, leaving a store that would
        // answer the next create with a negative name; the checked assignment
        // leaves the counter where it was, so the refusal simply repeats.
        self.next_seq = std.math.add(i64, seq, 1) catch return error.StoreFull;
        // The list slot is reserved BEFORE any I/O, and that ordering is
        // load-bearing rather than tidy. Appending after the create would put a
        // FALLIBLE allocation after the segment is already durable: the file
        // exists, its directory entry is fsynced, `sealed_bytes` has already
        // absorbed the segment this one displaces — and an `OutOfMemory` there
        // would leave a valid durable segment that the live set does not know
        // about, with a byte total that describes neither the old namespace nor
        // the new one. Rust cannot reach that state because `Vec::push` does not
        // report allocation failure; reserving here is how Zig does not either.
        // Failing at this point is safe and burns the name, which is what W6
        // requires of every failed create.
        self.segments.ensureUnusedCapacity(self.alloc, 1) catch return error.OutOfMemory;
        const path = try self.segmentFile(seq);
        var keep_path = false;
        defer if (!keep_path) self.alloc.free(path);
        const hdr = buildHeader(seq, first_lsn);

        try walIoEvent(self.io, .create, seq, 0, 0, 0);
        const file = std.fs.cwd().createFile(path, .{ .read = true, .exclusive = true }) catch
            return error.Io;
        {
            // Anything that fails between here and the directory fsync leaves a
            // partial segment the namespace must not carry: remove it and repeat
            // the refusal, exactly as Rust's fallible closure does.
            errdefer {
                file.close();
                std.fs.cwd().deleteFile(path) catch {};
            }
            try walIoEvent(self.io, .seg_header, seq, 0, SEG_HDR, 0);
            file.pwriteAll(&hdr, 0) catch return error.Io;
            try walIoEvent(self.io, .force_full, seq, SEG_HDR, 0, 0);
            // The file's SIZE is part of the payload here: never fdatasync.
            std.posix.fsync(file.handle) catch return error.Io;
            self.segment_syncs += 1;
            try self.fsyncDir();
        }
        // The Segment reopens on demand, like every other one.
        file.close();

        // The segment this one displaces stops growing here, so its length joins
        // the sealed total.
        if (self.segments.items.len > 0) {
            self.sealed_bytes += self.segments.items[self.segments.items.len - 1].file_len;
        }
        // Infallible: the slot was reserved before the create.
        self.segments.appendAssumeCapacity(Segment.init(seq, path, self.read_only, hdr, SEG_HDR));
        keep_path = true;
        return &self.segments.items[self.segments.items.len - 1];
    }

    /// W5: unlink every segment at or below `through_seq`, then fsync the
    /// directory. Called only after the `'K'` authorizing it is forced. A failed
    /// unlink is a leak that the next open retries (K5/K8) — never permission to
    /// advance an unproven mark.
    ///
    /// Ascending order is used for tidiness only. It does **not** make the
    /// crash-visible set a prefix: syscall order says nothing about the order
    /// removals persist before the fsync, so an interior gap is a legitimate crash
    /// image (N3/K9).
    pub fn unlinkThrough(self: *Self, through_seq: i64) DbError!void {
        if (self.closed) return error.StoreClosed;
        if (self.read_only or through_seq <= 0) return;
        var n: usize = 0;
        while (n < self.segments.items.len and self.segments.items[n].seq <= through_seq) n += 1;
        if (n == 0) {
            // No delete and NO directory fsync: this is the shape a recovered mark
            // takes when an earlier attempt already removed every file it
            // authorizes.
            return;
        }
        // Take them out of the live set BEFORE any delete can fail: their handles
        // are released here, so a failed unlink must not leave a
        // closed-but-listed segment behind for some later reader to use. The files
        // are then just a leak the next open retries.
        //
        // The retiring segments are moved out WHOLE, so the loop below still has
        // their paths and sequence numbers after the live list has forgotten
        // them. Capacity for the copy is reserved first: an allocation failure
        // must happen while the set is still intact, not half-way through
        // dismantling it.
        var retiring: std.ArrayListUnmanaged(Segment) = .empty;
        defer {
            for (retiring.items) |*s| s.deinit(self.alloc);
            retiring.deinit(self.alloc);
        }
        retiring.ensureTotalCapacity(self.alloc, n) catch return error.OutOfMemory;
        for (self.segments.items[0..n]) |*s| {
            s.release();
            retiring.appendAssumeCapacity(s.*);
        }
        const rest = self.segments.items.len - n;
        std.mem.copyForwards(Segment, self.segments.items[0..rest], self.segments.items[n..]);
        self.segments.shrinkRetainingCapacity(rest);
        // RECOMPUTED, not decremented: subtracting each removed length is correct
        // only while the highest segment is never in the prefix — true today (K4
        // plus R4's refusal of a mark that retires the whole set), but that is a
        // property of two other rules rather than of this method, and getting it
        // wrong drifts the counter silently in the direction that stops cleaning.
        self.recomputeSealedBytes();
        for (retiring.items) |s| {
            try walIoEvent(self.io, .unlink, s.seq, 0, 0, 0);
            try removeIfExists(s.path);
        }
        try self.fsyncDir();
    }

    pub fn fsyncDir(self: *Self) DbError!void {
        try walIoEvent(self.io, .dir_sync, 0, 0, 0, 0);
        // `.iterate` forces a real O_RDONLY dir fd (a default O_PATH fd cannot be
        // fsync'd on Linux → EBADF).
        var d = std.fs.cwd().openDir(self.dir, .{ .iterate = true }) catch return error.Io;
        defer d.close();
        std.posix.fsync(d.fd) catch return error.Io;
        self.dir_fsyncs += 1;
    }

    fn recomputeSealedBytes(self: *Self) void {
        self.sealed_bytes = 0;
        if (self.segments.items.len == 0) return;
        for (self.segments.items[0 .. self.segments.items.len - 1]) |s| {
            self.sealed_bytes += s.file_len;
        }
    }

    // ---------- accessors ----------
    //
    // **Every pointer and slice below borrows the segment list**, and the list is
    // an `ArrayListUnmanaged` that reallocates. A `*Segment` or `[]Segment` is
    // therefore valid only until the next call that changes which segments exist
    // — `createSegment`, `unlinkThrough`, `deleteNamespace`, `close`, `deinit`.
    // Rust states the same rule and the borrow checker enforces it; here it is a
    // rule, and B1's recovery passes and B2's writer both have to keep it. Re-ask
    // for the pointer after any such call; never cache one across one.

    pub fn segmentsSlice(self: *Self) []Segment {
        return self.segments.items;
    }

    /// The highest-sequence segment with a valid header, or `null` for a fresh
    /// store.
    pub fn active(self: *Self) ?*Segment {
        if (self.segments.items.len == 0) return null;
        return &self.segments.items[self.segments.items.len - 1];
    }

    pub fn nextSeq(self: *const Self) i64 {
        return self.next_seq;
    }

    pub fn isReadOnly(self: *const Self) bool {
        return self.read_only;
    }

    /// How many segments currently hold an open file handle. Steady state after
    /// recovery is at most one — the active segment — and that bound is the
    /// point, so it is observable rather than merely intended.
    pub fn openFileCount(self: *const Self) usize {
        var n: usize = 0;
        for (self.segments.items) |s| {
            if (s.file != null) n += 1;
        }
        return n;
    }

    /// Sum of the segment files' current lengths: what the log actually costs on
    /// the device. O(1).
    pub fn logBytes(self: *const Self) u64 {
        if (self.segments.items.len == 0) return 0;
        return self.sealed_bytes + self.segments.items[self.segments.items.len - 1].file_len;
    }

    /// The same number the slow way — to pin `sealed_bytes` against drift.
    pub fn logBytesExact(self: *const Self) u64 {
        var n: u64 = 0;
        for (self.segments.items) |s| n += s.file_len;
        return n;
    }

    /// **D2's lock-owning namespace cleanup**: delete every file this base owns —
    /// the segments, by the same enumeration rule the open used, plus
    /// `<base>.lock` — then fsync the directory once and release the lock.
    ///
    /// It runs WHILE THE LOCK IS STILL HELD, and that ordering is the whole point.
    /// Close-then-delete is racy in two ways: once close releases the lock a
    /// second opener can acquire the namespace and have its live segments deleted
    /// underneath it, and unlinking the lock PATHNAME while another instance may
    /// exist lets a third opener create a fresh lock inode and "acquire" a
    /// namespace someone else is already using. The lock file goes last, under the
    /// lock, as the owning instance's final act.
    ///
    /// Names that are not this base's segments are preserved: enumeration ignores
    /// them (N4), and a delete-after-close must not sweep a directory it was
    /// merely given a path into. Errors propagate — a best-effort delete would
    /// report a clean removal of files that are still there.
    pub fn deleteNamespace(self: *Self) DbError!void {
        if (self.closed) return error.StoreClosed;
        if (self.read_only) return error.ReadOnly;
        // RE-enumerated rather than taken from `segments`: the live list holds
        // what recovery retained, and the directory may also hold names this open
        // legitimately left behind (a read-only-style residue kept by an earlier
        // writer, an interior gap). All of them are this base's. CHECKED
        // enumeration: a directory this process cannot read is an error, never an
        // empty namespace (D2 requires propagation).
        var found = try self.enumerateChecked();
        defer found.deinit(self.alloc);
        for (found.items) |seq| {
            const path = try self.segmentFile(seq);
            defer self.alloc.free(path);
            try walIoEvent(self.io, .unlink, seq, 0, 0, 0);
            try removeIfExists(path);
        }
        self.clearSegments();
        self.sealed_bytes = 0;
        // The lock file is unlinked while its lock is still held, so no opener can
        // be between "created the inode" and "locked it" for THIS pathname.
        const lock_path = try self.withSuffix(".lock");
        defer self.alloc.free(lock_path);
        try removeIfExists(lock_path);
        try self.fsyncDir();
        self.close();
    }

    /// Releases every segment handle, then the store lock file, then this
    /// process's claim on the namespace — in that order.
    ///
    /// The set stays alive but is **closed**: the namespace mutations refuse from
    /// here on, because they would otherwise run without the lock that makes them
    /// safe. D2's cleanup must therefore delete while the set is still open and
    /// call this last.
    pub fn close(self: *Self) void {
        self.clearSegments();
        if (self.lock) |f| f.close();
        self.lock = null;
        if (self.claim) |*c| c.release();
        self.claim = null;
        self.closed = true;
    }

    /// [`close`](WalSegmentSet.close) plus the owned buffers. Rust reaches this
    /// through `Drop`; Zig needs it named, and every early return out of
    /// [`openWithIo`](WalSegmentSet.openWithIo) is wired to it.
    /// Idempotent: a caller that has already run `deleteNamespace` (which closes)
    /// still runs its `defer set.deinit()`, and so does one that closed by hand.
    pub fn deinit(self: *Self) void {
        self.close();
        self.segments.deinit(self.alloc);
        self.segments = .empty;
        self.alloc.free(self.prefix);
        self.alloc.free(self.base);
        self.base = &.{};
        self.prefix = &.{};
        self.dir = &.{};
    }

    fn clearSegments(self: *Self) void {
        for (self.segments.items) |*s| s.deinit(self.alloc);
        self.segments.clearRetainingCapacity();
    }

    /// `<base><suffix>`; owned, caller frees.
    fn withSuffix(self: *const Self, suffix: []const u8) DbError![]u8 {
        return std.mem.concat(self.alloc, u8, &.{ self.base, suffix }) catch
            error.OutOfMemory;
    }

    /// Records a diagnostic for the refusal the caller is about to return. It
    /// does not choose the error: `DataCorruption` is a verdict about bytes, and
    /// several of these refusals (`Locked`, `WrongConfiguration`) are operational
    /// and must not be mistaken for one.
    fn note(self: *Self, reason: []const u8, seq: i64) void {
        self.reason = reason;
        self.reason_seq = seq;
    }
};

// ------------------------------------------------------------ free functions

/// Reads and validates one segment header (table H).
fn readHeader(
    file: std.fs.File,
    len: u64,
    into: *[@as(usize, SEG_HDR)]u8,
    name_seq: i64,
) DbError!HeaderVerdict {
    if (len == 0) return .{ .kind = .torn, .reason = "empty segment file" }; // H1
    if (len < SEG_HDR) {
        return .{ .kind = .torn, .reason = "segment header truncated" }; // H2
    }
    const n = file.preadAll(into, 0) catch return error.Io;
    if (n < into.len) return .{ .kind = .torn, .reason = "segment header short read" };
    if (@as(i32, @bitCast(crc32(into[0..SEG_HDR_CRC_LEN]))) != getI32Be(into, SEG_HDR_CRC_LEN)) {
        return .{ .kind = .torn, .reason = "segment header CRC mismatch" }; // H3
    }
    if (!std.mem.eql(u8, into[0..8], &MAGIC)) {
        return .{ .kind = .torn, .reason = "not a mapdb WAL segment" }; // H4
    }
    if (getI32Be(into, 8) != FORMAT_VERSION) {
        return .{ .kind = .corrupt, .reason = "unsupported WAL format version" }; // H5
    }
    if (getI32Be(into, 12) != 0) {
        return .{ .kind = .corrupt, .reason = "unknown segment flags" }; // H6
    }
    if (getI64Be(into, 16) != name_seq) {
        return .{ .kind = .corrupt, .reason = "header sequence does not match its name" }; // H7
    }
    if (getI64Be(into, 24) <= 0) {
        return .{ .kind = .corrupt, .reason = "header firstLsn is not a valid LSN" }; // H9
    }
    return .{ .kind = .ok };
}

/// [`Segment.crcDomain`] for a caller holding header BYTES rather than a segment
/// — the section writer, which seals a section before the segment it extends has
/// been re-read, and the byte-level test kit.
pub fn crcDomainOf(crc: *Crc32, header: *const [@as(usize, SEG_HDR)]u8, section_offset: u64) void {
    crc.update(header);
    var off: [8]u8 = undefined;
    std.mem.writeInt(u64, &off, section_offset, .big);
    crc.update(&off);
}

/// The 36 header bytes a conforming writer produces for `(seq, first_lsn)`.
pub fn buildHeader(seq: i64, first_lsn: i64) [@as(usize, SEG_HDR)]u8 {
    var hdr: [@as(usize, SEG_HDR)]u8 = undefined;
    @memcpy(hdr[0..8], &MAGIC);
    std.mem.writeInt(i32, hdr[8..12], FORMAT_VERSION, .big);
    std.mem.writeInt(i32, hdr[12..16], 0, .big);
    std.mem.writeInt(i64, hdr[16..24], seq, .big);
    std.mem.writeInt(i64, hdr[24..32], first_lsn, .big);
    std.mem.writeInt(i32, hdr[32..36], @bitCast(crc32(hdr[0..SEG_HDR_CRC_LEN])), .big);
    return hdr;
}

fn allLowerHex(s: []const u8) bool {
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

/// Regular file, symlinks NOT followed — the N4/N6 discipline.
fn isRegularFile(path: []const u8) bool {
    const st = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch
        return false;
    return std.posix.S.ISREG(st.mode);
}

/// Something exists at this name, whatever it is — symlinks NOT followed, so a
/// dangling symlink counts as present. D1's `.ckpt` sentinel, and only that:
/// there the question is "is there something here I cannot account for", and a
/// link pointing nowhere is exactly that.
fn pathExistsNoFollow(path: []const u8) bool {
    _ = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch
        return false;
    return true;
}

/// Something openable exists at this name — symlinks FOLLOWED, so a dangling
/// symlink counts as absent. The store lock's ladder, where the question is "can
/// I still get a handle on this", which Rust asks as `Path::exists()` and Java as
/// `File.exists()`.
fn pathExistsFollowing(path: []const u8) bool {
    _ = std.posix.fstatat(std.posix.AT.FDCWD, path, 0) catch return false;
    return true;
}

fn removeIfExists(path: []const u8) DbError!void {
    std.fs.cwd().deleteFile(path) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return error.Io,
    };
}

// ----------------------------------------------------------- the process claim

const ClaimKey = struct { u64, u64 };

/// The `(device, inode)` of every store lock this process currently holds — the
/// port's copy of the JVM-wide lock table Java's `tryLock` consults (see
/// [`WalSegmentSet.takeStoreLock`] for why a kernel lock cannot stand in for it).
///
/// Process-global, so it carries its own allocator rather than a store's: the
/// table outlives every individual set. `page_allocator` because the table holds
/// a handful of 16-byte keys and is touched twice per store open.
var open_stores: std.ArrayListUnmanaged(ClaimKey) = .empty;
var open_stores_mu: std.Thread.Mutex = .{};
const open_stores_alloc = std.heap.page_allocator;

/// Membership in [`open_stores`]. Zig has no destructor, so every path that can
/// abandon a claim calls [`release`](ProcessClaim.release) explicitly; the
/// `errdefer` chain in `takeStoreLock` and `WalSegmentSet.close` are the two that
/// matter.
const ProcessClaim = struct {
    key: ClaimKey,
    released: bool = false,

    /// `null` when this process already holds that store, whatever the mode of
    /// either open.
    fn take(key: ClaimKey) error{OutOfMemory}!?ProcessClaim {
        open_stores_mu.lock();
        defer open_stores_mu.unlock();
        for (open_stores.items) |k| {
            if (k[0] == key[0] and k[1] == key[1]) return null;
        }
        try open_stores.append(open_stores_alloc, key);
        return ProcessClaim{ .key = key };
    }

    fn release(self: *ProcessClaim) void {
        if (self.released) return;
        self.released = true;
        open_stores_mu.lock();
        defer open_stores_mu.unlock();
        for (open_stores.items, 0..) |k, i| {
            if (k[0] == self.key[0] and k[1] == self.key[1]) {
                _ = open_stores.swapRemove(i);
                return;
            }
        }
    }
};

// ------------------------------------------------------------------ the lock

/// `F_OFD_SETLK`. Not in Zig's `std.posix.F` at 0.15, and architecture-INdependent
/// on Linux (unlike the `F_GETLK` family), so the literal is the whole contract.
const F_OFD_SETLK: i32 = 37;

/// A non-blocking whole-file OFD record lock, `F_WRLCK` or `F_RDLCK`.
/// `false` means another owner holds a conflicting lock; a real error propagates.
fn tryOfdLock(file: std.fs.File, exclusive: bool) DbError!bool {
    var fl: std.posix.Flock = std.mem.zeroes(std.posix.Flock);
    fl.type = if (exclusive) std.posix.F.WRLCK else std.posix.F.RDLCK;
    fl.whence = std.posix.SEEK.SET;
    fl.start = 0;
    // 0 means "to end of file, however the file grows" — Java's
    // `tryLock(0, Long.MAX_VALUE, shared)` covers the same whole-file range.
    fl.len = 0;
    while (true) {
        // Called through `std.os.linux` rather than `std.posix.fcntl` because
        // `F_OFD_SETLK` is not among the commands Zig's `std.posix.F` exposes, so
        // the command number has to be supplied as a literal either way. Going
        // one layer down keeps the errno classification in view beside the
        // constant it belongs to. (`std.posix.fcntl` would in fact classify
        // correctly — it retries EINTR and maps EAGAIN/EACCES to `error.Locked` —
        // so this is a legibility choice, not a correctness one.)
        const rc = std.os.linux.fcntl(file.handle, F_OFD_SETLK, @intFromPtr(&fl));
        switch (std.os.linux.E.init(rc)) {
            .SUCCESS => return true,
            // The documented "another owner holds it" answers. EWOULDBLOCK is the
            // same value as EAGAIN on Linux and has no separate name in Zig's
            // errno enum; POSIX permits either.
            .ACCES, .AGAIN => return false,
            // An interrupted syscall says NOTHING about another owner. Reporting
            // it as contention would refuse an open that a signal happened to land
            // on; retry, which is what a non-blocking acquisition can always
            // safely do.
            .INTR => continue,
            else => return error.Io,
        }
    }
}

/// `access(dir, W_OK)` — the same probe Java's `Files.isWritable` makes on Unix.
///
/// Note what it does NOT prove: it answers for this process's real credentials
/// only, so a `false` is evidence of a read-only medium rather than proof that no
/// writer can appear. See the caller.
fn isWritableDir(dir: []const u8) bool {
    // An interior NUL cannot name a real directory, and truncating at it would
    // silently probe a DIFFERENT path. Answer "writable", the conservative side:
    // it leads to the fail-closed refusal rather than to a lockless open.
    if (std.mem.indexOfScalar(u8, dir, 0) != null) return true;
    std.posix.access(dir, std.posix.W_OK) catch return false;
    return true;
}

// ------------------------------------------------------------------- tests
//
// The suite lives in `wal_segments_test.zig`. What stays here is what the suite
// cannot reach: the private lock primitive, whose exact semantics are the reason
// this port does not use `flock`.

const testing = std.testing;

// The KERNEL half of the store lock, exercised directly because the process
// claim refuses every in-process pair before the kernel ever sees it. OFD locks
// are owned by the open file description: two read locks share, a write lock is
// excluded by a read lock, and closing one description does not release
// another's lock — that last one is the defect that makes plain `F_SETLK`
// unusable here.
test "wal3 B0: OFD locks are owned by the open file description" {
    const path = "/tmp/mapdb5_walseg_ofd_semantics.lock";
    defer std.fs.cwd().deleteFile(path) catch {};
    const openOne = struct {
        fn f(p: []const u8) !std.fs.File {
            return std.fs.cwd().createFile(p, .{ .read = true, .truncate = false });
        }
    }.f;

    const a = try openOne(path);
    var a_open = true;
    defer if (a_open) a.close();
    const b = try openOne(path);
    var b_open = true;
    defer if (b_open) b.close();

    try testing.expect(try tryOfdLock(a, false)); // first read lock
    try testing.expect(try tryOfdLock(b, false)); // read locks share

    const w = try openOne(path);
    defer w.close();
    try testing.expect(!try tryOfdLock(w, true)); // a writer is excluded

    b.close();
    b_open = false;
    // Closing another description must not release a's lock. Under plain
    // `F_SETLK` it would, which is the whole reason for OFD.
    try testing.expect(!try tryOfdLock(w, true));

    a.close();
    a_open = false;
    try testing.expect(try tryOfdLock(w, true)); // released by the last owner

    // ...and an exclusive lock excludes a reader in the other direction.
    const r = try openOne(path);
    defer r.close();
    try testing.expect(!try tryOfdLock(r, false));
}
