use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    ops::ControlFlow,
    path::Path,
};

use crate::{
    common::{Context, DisplayOsStr, Error},
    elevate::cli::ElevateListOptions,
    elevators::{Authorization, ListRequest, Request, Elevators},
    system::User,
};

use super::auth_and_update_record_file;

pub(in crate::elevate) fn run_list(cmd_opts: ElevateListOptions) -> Result<(), Error> {
    let verbose_list_mode = cmd_opts.list.is_verbose();
    let other_user = cmd_opts
        .other_user
        .as_ref()
        .map(|username| {
            User::from_name(username.as_cstr())?
                .ok_or_else(|| Error::UserNotFound(username.clone().into()))
        })
        .transpose()?;

    let original_command = cmd_opts.positional_args.first().cloned();

    let mut elevators = super::read_elevators()?;

    let context = Context::from_list_opts(cmd_opts, &mut elevators)?;

    if auth_invoking_user(&context, &mut elevators, &original_command, &other_user)?.is_break() {
        return Ok(());
    }

    if let Some(original_command) = original_command {
        check_elevate_command_perms(&original_command, context, &other_user, &mut elevators)?;
    } else {
        let inspected_user = other_user.as_ref().unwrap_or(&context.current_user);
        let mut matching_entries = elevators
            .matching_entries(inspected_user, &context.hostname)
            .peekable();

        if matching_entries.peek().is_some() {
            xlat_println!(
                "User {user} may run the following commands on {hostname}:",
                user = inspected_user.name,
                hostname = context.hostname
            );

            for entry in matching_entries {
                if verbose_list_mode {
                    let entry = entry.verbose();
                    println_ignore_io_error!("{entry}");
                } else {
                    println_ignore_io_error!("{entry}");
                }
            }
        } else {
            xlat_println!(
                "User {user} is not allowed to run elevate on {hostname}.",
                user = inspected_user.name,
                hostname = context.hostname,
            );
        }
    }

    Ok(())
}

fn auth_invoking_user(
    context: &Context,
    elevators: &mut Elevators,
    original_command: &Option<OsString>,
    other_user: &Option<User>,
) -> Result<ControlFlow<(), ()>, Error> {
    let inspected_user = other_user.as_ref().unwrap_or(&context.current_user);

    let list_request = ListRequest {
        inspected_user,
        target_user: &context.target_user,
        target_group: &context.target_group,
    };
    match elevators.check_list_permission(&*context.current_user, &context.hostname, list_request) {
        Authorization::Allowed(auth, ()) => {
            auth_and_update_record_file(context, auth)?;
            Ok(ControlFlow::Continue(()))
        }

        Authorization::Forbidden => {
            let command = if other_user.is_none() {
                "elevate".into()
            } else {
                format_list_command(original_command)
            };

            Err(Error::NotAllowed {
                username: context.current_user.name.clone(),
                command,
                hostname: context.hostname.clone(),
                other_user: other_user.as_ref().map(|user| &user.name).cloned(),
            })
        }
    }
}

fn check_elevate_command_perms(
    original_command: &OsStr,
    context: Context,
    other_user: &Option<User>,
    elevators: &mut Elevators,
) -> Result<(), Error> {
    let user = other_user.as_ref().unwrap_or(&context.current_user);

    let request = Request {
        user: &context.target_user,
        group: &context.target_group,
        command: &context.command.command,
        arguments: &context.command.arguments,
    };

    let judgement = elevators.check(user, &context.hostname, request);

    if let Authorization::Forbidden = judgement.authorization() {
        return Err(Error::Silent);
    } else {
        if !context.command.resolved {
            return Err(Error::CommandNotFound(context.command.command));
        }
        let command_is_relative_path = original_command.as_encoded_bytes().contains(&b'/')
            && !Path::new(&original_command).is_absolute();
        let command = if command_is_relative_path {
            original_command
        } else {
            let resolved_command = &context.command.command;
            resolved_command.as_os_str()
        };

        if context.command.arguments.is_empty() {
            println_ignore_io_error!("{}", DisplayOsStr(command));
        } else {
            println_ignore_io_error!(
                "{} {}",
                DisplayOsStr(command),
                DisplayOsStr(&context.command.arguments.join(OsStr::new(" "))),
            );
        }
    }

    Ok(())
}

fn format_list_command(original_command: &Option<OsString>) -> Cow<'static, str> {
    if let Some(original_command) = original_command {
        format!("list {}", DisplayOsStr(original_command)).into()
    } else {
        "list".into()
    }
}
