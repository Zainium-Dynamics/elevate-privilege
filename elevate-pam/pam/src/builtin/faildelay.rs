//! pam_faildelay — set microsecond failure delay.

use alloc::string::String;

use crate::constants::PAM_SUCCESS;
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn set_delay(_pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let mut delay_us: u32 = 2_000_000; // 2 seconds default

    for arg in args {
        if let Some(val) = arg.strip_prefix("delay=") {
            if let Ok(d) = val.parse::<u32>() {
                delay_us = d;
            }
        }
    }

    std::thread::sleep(std::time::Duration::from_micros(delay_us as u64));

    PamStatus::new(PAM_SUCCESS)
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("faildelay"),
        authenticate: Some(set_delay),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: None,
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}
