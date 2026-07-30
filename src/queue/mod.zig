//! `queue` layer — persistent queue primitives over a Store4 store.
//!
//! - [`long.QueueLong`]: persistent FIFO of `(timestamp, value)` long pairs with
//!   O(1) removal / bump by node recid; a DIRECT store primitive (three pointer
//!   recids, no catalog object).
//! - [`blocking.PersistentBlockingQueue`]: generic serializer-based FIFO / LIFO
//!   stack / overwrite-on-full circular queue with blocking `take`/`put`.
//!
//! Both are byte-for-byte compatible with the Java encoders (golden-vector
//! tested); see each module's header for the wire format and concurrency notes.

const std = @import("std");

pub const long = @import("long.zig");
pub const blocking = @import("blocking.zig");

pub const QueueLong = long.QueueLong;
pub const QueueLongNode = long.Node;
pub const PersistentBlockingQueue = blocking.PersistentBlockingQueue;
pub const QueueMode = blocking.Mode;

test {
    std.testing.refAllDecls(@This());
}
