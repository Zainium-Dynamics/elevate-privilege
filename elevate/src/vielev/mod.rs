#![forbid(unsafe_code)]

mod cli;
mod help;

use std::{
    env, ffi,
    fs::{File, Permissions},
    io::{self, BufRead, Read, Seek, Write},
    os::unix::{
        fs::fchown,
        prelude::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    str,
};

use crate::{
    common::resolve::CurrentUser,
    elevate::{candidate_elevators_file, diagnostic},
    elevators::{self, Elevators},
    system::{
        Hostname, User,
        file::{FileLock, create_temporary_dir},
        interface::UserId,
        signal::{SignalStream, SignalsState, consts::*, register_handlers},
    },
};

use self::cli::{ViselevAction, ViselevOptions};
use self::help::{USAGE_MSG, long_help_message};

const VERSION: &str = env!("CARGO_PKG_VERSION");

macro_rules! io_msg {
    ($err:expr, $($tt:tt)*) => {
        io::Error::new($err.kind(), format!("{}: {}", format_args!($($tt)*), $err))
    };
}

pub fn main() {
    if User::effective_uid() != User::real_uid() || User::effective_gid() != User::real_gid() {
        println_ignore_io_error!(
            "Vielevate must not be installed as setuid binary.\n\
             Please notify your packager about this misconfiguration.\n\
             To prevent privilege escalation viselevate will now abort.
             "
        );
        std::process::exit(1);
    }

    let options = match ViselevOptions::from_env() {
        Ok(options) => options,
        Err(error) => {
            println_ignore_io_error!("viselev: {error}\n{USAGE_MSG}");
            std::process::exit(1);
        }
    };

    let cmd = match options.action {
        ViselevAction::Help => {
            println_ignore_io_error!("{}", long_help_message());
            std::process::exit(0);
        }
        ViselevAction::Version => {
            println_ignore_io_error!("viselev (zainium-elevators) {VERSION}");
            std::process::exit(0);
        }
        ViselevAction::Check => check,
        ViselevAction::Run => run,
    };

    match cmd(options.file.as_deref(), options.perms, options.owner) {
        Ok(()) => {}
        Err(error) => {
            eprintln_ignore_io_error!("viselev: {error}");
            std::process::exit(1);
        }
    }
}

fn check(file_arg: Option<&str>, perms: bool, owner: bool) -> io::Result<()> {
    let mut elevators_path = file_arg
        .map(PathBuf::from)
        .unwrap_or_else(candidate_elevators_file);

    let elevators_file = File::open(if elevators_path == Path::new("-") {
        // portability: /dev/stdin 'almost POSIX' and exists on BSD and Linux systems
        elevators_path = PathBuf::from("stdin");
        Path::new("/dev/stdin")
    } else {
        &elevators_path
    })
    .map_err(|err| io_msg!(err, "unable to open {}", elevators_path.display()))?;

    let metadata = elevators_file.metadata()?;

    if file_arg.is_none() || perms {
        // For some reason, the MSB of the mode is on so we need to mask it.
        let mode = metadata.permissions().mode() & 0o777;

        if mode != 0o440 {
            return Err(io::Error::other(format!(
                "{}: bad permissions, should be mode 0440, but found {mode:04o}",
                elevators_path.display()
            )));
        }
    }

    if file_arg.is_none() || owner {
        let owner = (metadata.uid(), metadata.gid());

        if owner != (0, 0) {
            return Err(io::Error::other(format!(
                "{}: wrong owner (uid, gid) should be (0, 0), but found {owner:?}",
                elevators_path.display()
            )));
        }
    }

    let (_elevators, errors) = Elevators::read(&elevators_file, &elevators_path)?;

    if errors.is_empty() {
        writeln!(io::stdout(), "{}: parsed OK", elevators_path.display())?;
        return Ok(());
    }

    for crate::elevators::Error {
        message,
        source,
        location,
    } in errors
    {
        let path = source.as_deref().unwrap_or(&elevators_path);
        diagnostic::diagnostic!("syntax error: {message}", path @ location);
    }

    Err(io::Error::other("invalid elevators config file"))
}

fn run(file_arg: Option<&str>, perms: bool, owner: bool) -> io::Result<()> {
    let elevators_path = &file_arg
        .map(PathBuf::from)
        .unwrap_or_else(candidate_elevators_file);

    let (elevators_file, existed) = if elevators_path.exists() {
        let file = File::options()
            .read(true)
            .write(true)
            .open(elevators_path)
            .map_err(|err| {
                io_msg!(
                    err,
                    "Failed to open existing elevators config file at {elevators_path:?}"
                )
            })?;

        (file, true)
    } else {
        // Create a elevators file if it doesn't exist.
        let file = File::create(elevators_path)
            .map_err(|err| io_msg!(err, "Failed to create elevators config file at {elevators_path:?}"))?;

        // ogvisudo sets the permissions of the file so it can be read and written by the user and
        // read by the group if the `-f` argument was passed.
        if file_arg.is_some() {
            file.set_permissions(Permissions::from_mode(0o640))
                .map_err(|err| {
                    io_msg!(
                        err,
                        "Failed to set permissions on new elevators config file at {elevators_path:?}"
                    )
                })?;
        }
        (file, false)
    };

    let lock = FileLock::exclusive(&elevators_file, true).map_err(|err| {
        if err.kind() == io::ErrorKind::WouldBlock {
            io_msg!(err, "{} busy, try again later", elevators_path.display())
        } else {
            err
        }
    })?;

    if perms || file_arg.is_none() {
        elevators_file.set_permissions(Permissions::from_mode(0o440))?;
    }

    if owner || file_arg.is_none() {
        fchown(&elevators_file, Some(0), Some(0))?;
    }

    let signal_stream = SignalStream::init()?;

    let handlers = register_handlers(
        [SIGTERM, SIGHUP, SIGINT, SIGQUIT],
        &mut SignalsState::save()?,
    )?;

    let tmp_dir = create_temporary_dir()?;
    let tmp_path = tmp_dir.join("elevators");

    {
        let tmp_dir = tmp_dir.clone();
        std::thread::spawn(|| -> io::Result<()> {
            signal_stream.recv()?;

            let _ = std::fs::remove_dir_all(tmp_dir);

            drop(handlers);

            std::process::exit(1)
        });
    }

    let tmp_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)?;

    tmp_file.set_permissions(Permissions::from_mode(0o600))?;

    let result = edit_elevators_file(
        existed,
        elevators_file,
        elevators_path,
        lock,
        tmp_file,
        &tmp_path,
    );

    std::fs::remove_dir_all(tmp_dir)?;

    result
}

fn edit_elevators_file(
    existed: bool,
    mut elevators_file: File,
    elevators_path: &Path,
    lock: FileLock,
    mut tmp_file: File,
    tmp_path: &Path,
) -> io::Result<()> {
    let mut stderr = io::stderr();

    let mut elevators_contents = Vec::new();

    // Since visudo is meant to run as root, resolve shouldn't fail
    let current_user: User = match CurrentUser::resolve() {
        Ok(user) => user.into(),
        Err(err) => {
            writeln!(stderr, "viselev: cannot resolve : {err}")?;
            return Ok(());
        }
    };

    let host_name = Hostname::resolve();

    if existed {
        // If the elevators file existed, read its contents and write them into the temporary file.
        elevators_file.read_to_end(&mut elevators_contents)?;
        // Rewind the elevators file so it can be written later.
        elevators_file.rewind()?;
        // Write to the temporary file.
        tmp_file.write_all(&elevators_contents)?;
    }

    let editor_path = Elevators::read(elevators_contents.as_slice(), elevators_path)?
        .0
        .viselev_editor_path(&host_name, &current_user, &current_user)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no usable editor could be found")
        })?;

    loop {
        Command::new(&editor_path.0)
            .args(&editor_path.1)
            .arg("--")
            .arg(tmp_path)
            .spawn()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "specified editor ({}) could not be used",
                        editor_path.0.display()
                    ),
                )
            })?
            .wait_with_output()?;

        let (elevators, errors) = File::open(tmp_path)
            .and_then(|reader| Elevators::read(reader, elevators_path))
            .map_err(|err| {
                io_msg!(
                    err,
                    "unable to re-open temporary file ({}), {} unchanged",
                    tmp_path.display(),
                    elevators_path.display()
                )
            })?;

        if !errors.is_empty() {
            writeln!(
                stderr,
                "The provided elevators config file format is not recognized or contains syntax errors. Please review:\n"
            )?;

            for crate::elevators::Error {
                message,
                source,
                location,
            } in errors
            {
                let path = source.as_deref().unwrap_or(elevators_path);
                diagnostic::diagnostic!("syntax error: {message}", path @ location);
            }

            writeln!(stderr)?;

            match ask_response(
                "What now? e(x)it without saving / (e)dit again: ",
                "xe",
                'x',
            )? {
                'x' => return Ok(()),
                _ => continue,
            }
        } else {
            if elevators_path == Path::new(&elevate_paths::get().elevators_file)
                && viselev_edit_is_allowed(elevators, &host_name) == Some(false)
            {
                writeln!(
                    stderr,
                    "It looks like you have removed your ability to run 'elevate viselev' again.\n"
                )?;
                match ask_response(
                    "What now? e(x)it without saving / (e)dit again / lock me out and (S)ave: ",
                    "xeS",
                    'x',
                )? {
                    'x' => return Ok(()),
                    'S' => {}
                    _ => continue,
                }
            }

            break;
        }
    }

    let tmp_contents = std::fs::read(tmp_path)?;
    // Only write to the elevators config   file if the contents changed.
    if tmp_contents == elevators_contents {
        writeln!(stderr, "viselev: {} unchanged", tmp_path.display())?;
    } else {
        elevators_file.write_all(&tmp_contents)?;
        let new_size = elevators_file.stream_position()?;
        elevators_file.set_len(new_size)?;
    }

    lock.unlock()?;

    Ok(())
}

// To detect potential lock-outs if the user called "sudo visudo".
// Note that ELEVATE_USER will normally be set by elevate.
//
// This returns Some(false) if viselev is forbidden under the given config;
// Some(true) if it is allowed; and None if it cannot be determined, which
// will be the case if e.g. viselev was simply run as root.
fn viselev_edit_is_allowed(mut elevators: Elevators, host_name: &Hostname) -> Option<bool> {
    let elevate_user =
        User::from_name(&ffi::CString::new(env::var("ELEVATE_USER").ok()?).ok()?).ok()??;

    let super_user = User::from_uid(UserId::ROOT).ok()??;

    let request = elevators::Request {
        user: &super_user,
        group: &super_user.primary_group().ok()?,
        command: &env::current_exe().ok()?,
        arguments: &[],
    };

    Some(matches!(
        elevators
            .check(&elevate_user, host_name, request)
            .authorization(),
        elevators::Authorization::Allowed { .. }
    ))
}

// This will panic if valid_responses is empty.
pub(crate) fn ask_response(
    prompt: &str,
    valid_responses: &str,
    safe_choice: char,
) -> io::Result<char> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stderr = io::stderr();

    let stdin_handle = stdin.lock();
    let mut stdout_handle = stdout.lock();

    let mut lines = stdin_handle.lines();

    loop {
        stdout_handle.write_all(prompt.as_bytes())?;
        stdout_handle.flush()?;

        match lines.next() {
            Some(Ok(answer))
                if answer
                    .chars()
                    .next()
                    .is_some_and(|input| valid_responses.contains(input)) =>
            {
                return Ok(answer.chars().next().unwrap());
            }
            Some(Ok(answer)) => writeln!(stderr, "Invalid option: '{answer}'\n",)?,
            Some(Err(err)) => writeln!(stderr, "Invalid response: {err}\n",)?,
            None => {
                writeln!(stderr, "viselev: cannot read user input")?;
                return Ok(safe_choice);
            }
        }
    }
}
