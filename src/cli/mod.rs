//! CLI subcommand handlers.
//!
//! Each submodule handles one group of CLI subcommands:
//! - `policy_test`: `omamori test` + policy test harness
//! - `install`: `omamori install` / `omamori uninstall`
//! - `status`: `omamori status`
//! - `audit_cmd`: `omamori audit verify/show/key`
//! - `config_cmd`: `omamori config/override/init` + config mutation

pub(crate) mod audit_cmd;
pub(crate) mod config_cmd;
pub(crate) mod install;
pub(crate) mod policy_test;
pub(crate) mod status;
