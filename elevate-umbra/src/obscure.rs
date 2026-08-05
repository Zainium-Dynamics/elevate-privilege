//! Password quality and complexity checker.
//! Port of shadow-4.17.2 `lib/obscure.c`.

use crate::login_defs::LoginDefs;

/// Check password strength and return an error message if it fails quality checks.
pub fn check_password_quality(new_pass: &str, old_pass: Option<&str>, username: &str) -> Result<(), String> {
    let login_defs = LoginDefs::load_default();
    let min_len = login_defs.pass_min_len().max(6); // Enforce absolute minimum 6 characters

    // 1. Length Check (minimum 6 characters)
    if new_pass.len() < min_len {
        return Err(format!("password length must be at least {} characters", min_len));
    }

    // 2. Username vs Password Equality Check
    let lower_pass = new_pass.to_lowercase();
    let lower_user = username.to_lowercase();
    if lower_pass == lower_user || lower_pass.contains(&lower_user) {
        return Err("username and password must be different (password cannot contain username)".to_string());
    }
    let rev_user: String = lower_user.chars().rev().collect();
    if lower_pass == rev_user {
        return Err("password cannot be the reversed username".to_string());
    }

    // 3. Palindrome Check
    let rev_pass: String = lower_pass.chars().rev().collect();
    if lower_pass == rev_pass {
        return Err("password cannot be a palindrome".to_string());
    }

    // 4. Require Capital Letter
    let has_uppercase = new_pass.chars().any(|c| c.is_uppercase());
    if !has_uppercase {
        return Err("password must contain at least one uppercase capital letter (A-Z)".to_string());
    }

    // 5. Require Special Character
    let has_special = new_pass.chars().any(|c| c.is_ascii_punctuation() || !c.is_alphanumeric());
    if !has_special {
        return Err("password must contain at least one special character (!@#$%^&*...)".to_string());
    }

    // 6. Require Number
    let has_number = new_pass.chars().any(|c| c.is_numeric());
    if !has_number {
        return Err("password must contain at least one number (0-9)".to_string());
    }

    // 7. Old Password Match Check
    if let Some(old) = old_pass {
        if new_pass == old {
            return Err("password is unchanged".to_string());
        }
        let lower_old = old.to_lowercase();
        if lower_pass == lower_old {
            return Err("password differs only by letter case".to_string());
        }
    }

    Ok(())
}
