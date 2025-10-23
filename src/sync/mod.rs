pub mod auth;
pub mod battery;
pub mod blob;
pub mod client;
pub mod dedup;
pub mod penalty;
pub mod range;
pub mod worker;

pub const MAX_SYNC_WIRE: usize = 2 * 1024 * 1024 + 64 * 1024;
