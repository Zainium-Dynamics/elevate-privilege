#![deny(unsafe_code)]

use crate::common::Error;
use crate::common::resolve::CurrentUser;
use crate::log::dev_info;
use crate::system::User;
use crate::system::interface::UserId;
use crate::system::timestamp::RecordScope;
use crate::system::{Process, timestamp::SessionRecordFile};
#[cfg(test)]
pub(crate) use cli::ElevateAction;
#[cfg(not(test))]
use cli::ElevateAction;
use std::{path::PathBuf, time::Duration};

mod cli;
pub(crate) use cli::{
    ElevateEditOptions, ElevateListOptions, ElevateRunOptions, ElevateValidateOptions,
};
mod edit;

pub(crate) mod diagnostic;
mod env;
pub(crate) use env::environment::path_default;
mod pam;
mod pipeline;

#[cfg_attr(not(feature = "dev"), allow(dead_code))]
fn unstable_warning() {
    let check_var = std::env::var("ELEVATE_IS_UNSTABLE").unwrap_or_else(|_| "".to_string());

    if check_var != "I accept that my system may break unexpectedly" {
        eprintln_ignore_io_error!(
            "WARNING!
Elevate is compiled with development logs on, which means it is less secure and could potentially
break your system. We recommend that you do not run this on any production environment.
To turn off this warning and use elevate you need to set the environment variable
ELEVATE_IS_UNSTABLE to the value `I accept that my system may break unexpectedly`."
        );

        std::process::exit(1);
    }
}

const VERSION: &str = if let Some(version_override) = std::option_env!("ELEVATE_VERSION") {
    version_override
} else {
    std::env!("CARGO_PKG_VERSION")
};

pub(crate) fn candidate_elevators_file() -> PathBuf {
    let mut path = PathBuf::from(&elevate_paths::get().elevators_file);
    if !path.exists() {
        let sys_path = PathBuf::from("/etc/elevators/elevate.toml");
        let legacy_rs = PathBuf::from("/etc/elevators-rs");
        let legacy = PathBuf::from("/etc/elevators");
        if sys_path.exists() {
            path = sys_path;
        } else if legacy_rs.exists() {
            path = legacy_rs;
        } else if legacy.exists() {
            path = legacy;
        }
    };

    dev_info!("Running with {} file", path.display());
    path
}

fn elevate_process() -> Result<(), Error> {
    crate::log::ElevateLogger::new("elevate: ").into_global_logger();

    dev_info!("development logs are enabled");

    #[cfg(feature = "gettext")]
    crate::gettext::textdomain(c"elevate");

    self_check()?;

    let usage_msg: &str;
    let long_help: fn() -> String;
    if cli::is_elevatedit(std::env::args_os().next()) {
        usage_msg = cli::help_edit::usage_msg();
        long_help = cli::help_edit::long_help_message;
    } else {
        usage_msg = cli::help::usage_msg();
        long_help = cli::help::long_help_message;
    }

    // parse cli options
    match ElevateAction::from_env() {
        Ok(action) => match action {
            ElevateAction::Help(_) => {
                println_ignore_io_error!("{}", long_help());
                std::process::exit(0);
            }
            ElevateAction::Version(_) => {
                println_ignore_io_error!("elevate-privilege {VERSION}");
                std::process::exit(0);
            }
            ElevateAction::RemoveTimestamp(_) => {
                let user = CurrentUser::resolve()?;
                let mut record_file = SessionRecordFile::open_for_user(&user, Duration::default())?;
                record_file.reset()?;
                Ok(())
            }
            ElevateAction::ResetTimestamp(_) => {
                if let Some(scope) = RecordScope::for_process(&Process::new()) {
                    let user = CurrentUser::resolve()?;
                    let mut record_file =
                        SessionRecordFile::open_for_user(&user, Duration::default())?;
                    record_file.disable(scope)?;
                }
                Ok(())
            }
            ElevateAction::Validate(options) => pipeline::run_validate(options),
            ElevateAction::Run(options) => {
                #[cfg(feature = "dev")]
                unstable_warning();

                // ElevateAction::from_env() should already ensure this
                assert!(!options.positional_args.is_empty() || options.shell || options.login);

                pipeline::run(options)
            }
            ElevateAction::List(options) => pipeline::run_list(options),
            ElevateAction::Edit(options) => pipeline::run_edit(options),
        },
        Err(e) => {
            eprintln_ignore_io_error!("{e}\n{}", usage_msg);
            std::process::exit(1);
        }
    }
}

fn self_check() -> Result<(), Error> {
    if User::effective_uid() != UserId::ROOT {
        #[cfg(target_os = "linux")]
        if crate::system::audit::no_new_privs_enabled()? {
            return Err(Error::SelfCheckNoNewPrivs);
        }

        return Err(Error::SelfCheckSetuid);
    }

    Ok(())
}

pub fn main() {
    match elevate_process() {
        Ok(()) => (),
        Err(error) => {
            if !error.is_silent() {
                diagnostic::diagnostic!("{error}");
            }
            std::process::exit(1);
        }
    }
}
