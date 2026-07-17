//! The C ABI is intentionally not exported until generated headers and memory-safety tests land.
//!
//! Go consumes this crate as a signed native library. Keeping the placeholder free of raw pointers
//! prevents an unaudited ABI from becoming public by accident.

/// ABI version reserved for the first generated header.
pub const STOGAS_VERIFIER_ABI_VERSION: u32 = 1;
