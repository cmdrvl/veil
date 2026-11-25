//! Compilers for the opt-in OS sandbox described by ADR B-1.
//!
//! These modules compile merged policy into backend rules. Compilation alone
//! does not confine a process; callers must apply the result before launching
//! the harness and must report that enforcement was applied only after it
//! succeeds.

pub mod landlock;
pub mod seatbelt;
