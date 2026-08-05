#[macro_use]
mod macros;
#[macro_use]
pub(crate) mod gettext;

#[cfg(feature = "apparmor")]
pub(crate) mod apparmor;
pub(crate) mod common;
pub(crate) mod core_protector;
pub(crate) mod cutils;
pub(crate) mod defaults;
pub(crate) mod exec;
pub(crate) mod log;
pub(crate) mod pam;
pub(crate) mod elevators;
pub(crate) mod system;

mod elev;
mod elevate;
mod vielev;

pub use elev::main as su_main;
pub use elevate::main as elevate_main;
pub use vielev::main as viselev_main;

#[cfg(feature = "do-not-use-all-features")]
compile_error!("Refusing to compile using 'cargo --all-features' --- please read the README");
