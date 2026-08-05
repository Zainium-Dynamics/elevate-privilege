//! Centralized exit codes matching shadow-4.17.2 `lib/exitcodes.h`.

/// Success.
pub const E_SUCCESS: i32 = 0;
/// Permission denied.
pub const E_NOPERM: i32 = 1;
/// Invalid command syntax / usage error.
pub const E_USAGE: i32 = 2;
/// Invalid argument to option.
pub const E_BAD_ARG: i32 = 3;
/// UID already in use (useradd).
pub const E_UID_IN_USE: i32 = 4;
/// Specified group doesn't exist.
pub const E_NOTFOUND: i32 = 6;
/// Username/groupname already in use.
pub const E_NAME_IN_USE: i32 = 9;
/// Can't update group file.
pub const E_GRP_UPDATE: i32 = 10;
/// Can't create home directory.
pub const E_HOMEDIR: i32 = 12;
/// Can't update SELinux user mapping (N/A for ZainiumOS).
pub const E_SE_UPDATE: i32 = 13;
/// Not found password file.
pub const E_PASSWD_NOTFOUND: i32 = 14;
/// Not found shadow password file.
pub const E_SHADOW_NOTFOUND: i32 = 15;
/// Not found group file.
pub const E_GROUP_NOTFOUND: i32 = 16;
/// Not found shadow group file.
pub const E_GSHADOW_NOTFOUND: i32 = 17;
/// Can't run command/shell.
pub const E_CMD_NOEXEC: i32 = 126;
/// Can't find command/shell to run.
pub const E_CMD_NOTFOUND: i32 = 127;
