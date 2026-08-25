//! # elevate-pam
//!
//! Authentication framework for the **elevate** tool family
//! (`elevate` / `elev` / `viselev`). Ships as `libelevate_pam.so`.
//!
//! License: **MIT OR Apache-2.0** (`SPDX-License-Identifier: MIT OR Apache-2.0`).
//!
//! ## Design
//!
//! - **elevate product line** — same naming as the sudo/su replacement, not a
//!   third-party “Linux-PAM distro package” rebrand.
//! - **TOML-only** service stacks under `/etc/elevate-pam/services/` (no JSON).
//! - **No `/usr`** — Zainium paths are `/bin`, `/sbin`, `/lib`, `/etc`.
//! - **shared / static / standalone** build categories via `elevate-pam.toml`.
//! - **Unified `std` + `no_std`** in one crate.
//! - **C `pam_*` ABI** so elevate can `dlopen("libelevate_pam.so")` at runtime
//!   (musl static binaries stay free of link-time `-lpam`).
//!
//! ## Build categories
//!
//! | Category     | Feature       | Behaviour                         |
//! |--------------|---------------|-----------------------------------|
//! | `shared`     | `shared`      | `libelevate_pam.so` + dlopen mods |
//! | `static`     | `static`      | archive + builtin registry        |
//! | `standalone` | `standalone`  | CLI / embedded stack              |

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod constants;
pub mod error;
pub mod types;

#[cfg(feature = "alloc")]
pub mod config;

#[cfg(feature = "alloc")]
pub mod handle;

#[cfg(feature = "alloc")]
pub mod item;

#[cfg(feature = "alloc")]
pub mod env;

#[cfg(feature = "alloc")]
pub mod data;

#[cfg(feature = "alloc")]
pub mod conv;

#[cfg(feature = "alloc")]
pub mod module;

#[cfg(feature = "alloc")]
pub mod dispatch;

#[cfg(feature = "alloc")]
pub mod securemem;

#[cfg(feature = "std")]
pub mod delay;

#[cfg(feature = "std")]
pub mod log;

#[cfg(feature = "std")]
pub mod loader;

#[cfg(all(feature = "std", feature = "legacy_pamd"))]
pub mod legacy_pamd;

#[cfg(feature = "std")]
pub mod ffi;

#[cfg(feature = "std")]
pub mod appl;

#[cfg(feature = "builtin_modules")]
pub mod builtin;

pub use constants::*;
pub use error::{PamError, PamResult, PamStatus};
pub use types::*;

#[cfg(feature = "alloc")]
pub use config::{
    BuildCategory, BuildConfig, ControlFlag, GlobalConfig, ModuleEntry, ServiceConfig, StackType,
};
#[cfg(feature = "alloc")]
pub use handle::PamHandle;
#[cfg(feature = "alloc")]
pub use module::{ModuleFn, ModuleHooks, ModuleId};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Advertise compatibility with Linux-PAM major/minor (ABI surface).
pub const LINUX_PAM_COMPAT_MAJOR: u32 = 1;
/// Minor compatibility version.
pub const LINUX_PAM_COMPAT_MINOR: u32 = 7;
