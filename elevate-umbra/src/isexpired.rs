//! Account and password expiration checking logic.
//! Port of shadow-4.17.2 `lib/isexpired.c`.

use crate::login_defs::LoginDefs;
use crate::shadow::ShadowEntry;

#[derive(Debug, PartialEq, Eq)]
pub enum ExpiryStatus {
    Ok,
    PasswordExpired,
    PasswordWarning(i64), // Days remaining
    AccountExpired,
    AccountInactive,
}

/// Check the expiration status of a shadow entry against current day count and login.defs.
pub fn check_expiration(entry: &ShadowEntry, today: i64, defs: &LoginDefs) -> ExpiryStatus {
    // 1. Absolute account expiration (sp_expire)
    if let Some(expire) = entry.expire {
        if expire > 0 && today > expire {
            return ExpiryStatus::AccountExpired;
        }
    }

    let max_days = entry.max.unwrap_or(defs.pass_max_days());
    let lstchg = entry.lstchg.unwrap_or(0);

    // 2. Account inactivity period after password expiration (sp_inact)
    if let Some(inact) = entry.inact {
        if inact > 0 && max_days < 99999 && today > (lstchg + max_days + inact) {
            return ExpiryStatus::AccountInactive;
        }
    }

    // 3. Password expiration (sp_max)
    if max_days > 0 && max_days < 99999 && today > (lstchg + max_days) {
        return ExpiryStatus::PasswordExpired;
    }

    // 4. Password expiration warning period (sp_warn)
    let warn_days = entry.warn.unwrap_or(defs.pass_warn_age());
    if max_days > 0 && max_days < 99999 && warn_days > 0 {
        let expire_at = lstchg + max_days;
        if today >= (expire_at - warn_days) && today <= expire_at {
            let days_left = expire_at - today;
            return ExpiryStatus::PasswordWarning(days_left.max(0));
        }
    }

    ExpiryStatus::Ok
}
