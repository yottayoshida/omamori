//! Core command evaluation engine: hook pipeline, shim execution, and guards.
//!
//! Submodules:
//! - `hook`: Hook input parsing, command checking, protected file detection
//! - `shim`: PATH shim execution, command evaluation pipeline, hook integrity
//! - `exec`: `omamori exec` subcommand handler
//! - `guard`: AI environment guard for config-mutating operations

pub(crate) mod exec;
pub(crate) mod guard;
pub(crate) mod hook;
pub(crate) mod shim;
