//! `btree` layer — ordered maps over a Store4 store.
//!
//! This layer provides `BTreeMap` (B-link tree: push-down readers + Lehman-Yao
//! concurrent writers), `TreePump` bulk loading, and the shared navigable
//! `RangeView` layer + columnar scan.
//!
//! `node` mirrors Java's PRIVATE `BTreeMap.Node`/`NodeSerializer`: it is not
//! re-exported from `root.zig`, so no external caller can construct a
//! structurally-impossible node and slip it past the byte-side validation into
//! the object read path. All persisted nodes are validated in
//! `NodeSerializer.deserialize`.

const std = @import("std");

pub const node = @import("node.zig");
pub const map = @import("map.zig");
pub const view = @import("view.zig");
pub const pump = @import("pump.zig");
pub const btree_test = @import("btree_test.zig");

pub const BTreeMap = map.BTreeMap;
pub const RangeView = view.RangeView;
pub const TreePump = pump.TreePump;

test {
    std.testing.refAllDecls(@This());
}
