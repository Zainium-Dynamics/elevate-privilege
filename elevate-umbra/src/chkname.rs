//! Name validation for user and group names.
//! Port of shadow-4.17.2 `lib/chkname.c` — enforces POSIX naming rules.
//!
//! Valid names match BRE: [a-zA-Z0-9_.][a-zA-Z0-9_.-]*$?
//! - Must not be empty
//! - Must not be "." or ".."
//! - Must not be fully numeric
//! - Optional trailing '$' (Samba machine accounts)
//! - Max length: LOGIN_NAME_MAX (256)

use crate::config::LOGIN_NAME_MAX;

/// Maximum group name size.
pub const GROUP_NAME_MAX: usize = 256;

/// Check if a character is valid as the first character of a user/group name.
fn is_valid_first_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

/// Check if a character is valid in the body of a user/group name.
fn is_valid_body_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

/// Core name validation logic (shared between user and group names).
///
/// Returns `Ok(())` if valid, `Err(reason)` if invalid.
fn validate_name(name: &str, max_len: usize) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("name is empty");
    }

    if name.len() >= max_len {
        return Err("name exceeds maximum length");
    }

    // Reject "." and ".."
    if name == "." || name == ".." {
        return Err("name cannot be '.' or '..'");
    }

    let mut chars = name.chars().peekable();

    // First character validation
    let first = chars.next().unwrap();
    if !is_valid_first_char(first) {
        return Err("name must start with a letter, digit, underscore, or dot");
    }

    let mut all_digits = first.is_ascii_digit();

    // Body characters
    while let Some(&c) = chars.peek() {
        chars.next();
        if chars.peek().is_none() && c == '$' {
            // Allow trailing '$' for Samba machine accounts
            break;
        }
        if !is_valid_body_char(c) {
            return Err("name contains invalid characters (only a-z, A-Z, 0-9, _, ., - allowed)");
        }
        all_digits &= c.is_ascii_digit();
    }

    // Fully numeric names are not allowed
    if all_digits {
        return Err("name cannot be fully numeric");
    }

    // Reject names containing ':'  (would break colon-delimited files)
    if name.contains(':') {
        return Err("name cannot contain ':'");
    }

    // Reject names containing NUL or newlines
    if name.contains('\0') || name.contains('\n') || name.contains('\r') {
        return Err("name cannot contain NUL or newline characters");
    }

    Ok(())
}

/// Validate a user name according to shadow-4.17.2 rules.
///
/// ```
/// use elevate_umbra::chkname::is_valid_user_name;
/// assert!(is_valid_user_name("alizain").is_ok());
/// assert!(is_valid_user_name("..").is_err());
/// assert!(is_valid_user_name("12345").is_err());
/// ```
pub fn is_valid_user_name(name: &str) -> Result<(), &'static str> {
    validate_name(name, LOGIN_NAME_MAX)
}

/// Validate a group name according to shadow-4.17.2 rules.
pub fn is_valid_group_name(name: &str) -> Result<(), &'static str> {
    validate_name(name, GROUP_NAME_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(is_valid_user_name("root").is_ok());
        assert!(is_valid_user_name("alizain").is_ok());
        assert!(is_valid_user_name("_apt").is_ok());
        assert!(is_valid_user_name("user.name").is_ok());
        assert!(is_valid_user_name("user-name").is_ok());
        assert!(is_valid_user_name("samba$").is_ok()); // Samba machine account
    }

    #[test]
    fn invalid_names() {
        assert!(is_valid_user_name("").is_err());
        assert!(is_valid_user_name(".").is_err());
        assert!(is_valid_user_name("..").is_err());
        assert!(is_valid_user_name("12345").is_err());
        assert!(is_valid_user_name("-invalid").is_err());
        assert!(is_valid_user_name("user:name").is_err());
        assert!(is_valid_user_name("user\nname").is_err());
    }

    #[test]
    fn group_names() {
        assert!(is_valid_group_name("wheel").is_ok());
        assert!(is_valid_group_name("sys-admins").is_ok());
        assert!(is_valid_group_name("999").is_err());
    }
}
