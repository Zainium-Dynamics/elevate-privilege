//! Module stack dispatch (Linux-PAM `_pam_dispatch` semantics).

use alloc::vec::Vec;

use crate::config::{BuildCategory, ControlFlag, ModuleEntry};
use crate::constants::*;
#[cfg(not(feature = "std"))]
use crate::error::PamError;
use crate::error::{PamResult, PamStatus};
use crate::handle::PamHandle;
use crate::types::{Action, StackKind};

#[cfg(feature = "std")]
use crate::module::resolve_module;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Impression {
    Undef,
    Positive,
    Negative,
}

/// Dispatch the configured stack for `kind`.
pub fn dispatch(pamh: &mut PamHandle, flags: i32, kind: StackKind) -> PamResult<PamStatus> {
    let entries: Vec<ModuleEntry> = pamh.service.stack_for(kind).to_vec();
    if entries.is_empty() {
        #[cfg(feature = "std")]
        crate::log::error(
            pamh,
            &alloc::format!(
                "no modules loaded for `{}` service ({})",
                pamh.service(),
                kind.as_str()
            ),
        );
        return Ok(PamStatus::new(PAM_PERM_DENIED));
    }

    let category = pamh.global.build.primary_category();
    let module_dir = pamh.global.paths.module_dir.clone();

    let mut impression = Impression::Undef;
    let mut status = PAM_PERM_DENIED;
    let mut cache: Vec<i32> = Vec::with_capacity(entries.len());

    let mut i = 0usize;
    while i < entries.len() {
        let entry = &entries[i];

        // include / substack: load nested service and run (simplified: same file refs)
        if matches!(entry.control, ControlFlag::Include | ControlFlag::Substack) {
            let nested_name = &entry.module;
            #[cfg(feature = "std")]
            {
                match crate::config::ServiceConfig::load_service(pamh.global(), nested_name) {
                    Ok(nested) => {
                        let nested_entries = nested.stack_for(kind).to_vec();
                        let sub = dispatch_entries(
                            pamh,
                            flags,
                            kind,
                            &nested_entries,
                            category,
                            &module_dir,
                        )?;
                        // merge sub result like a single module with required semantics
                        let act = ControlFlag::Required.actions();
                        let code = sub.code();
                        let action = action_for(&act, code);
                        match apply_action(action, code, &mut impression, &mut status) {
                            ControlFlow::Continue => {}
                            ControlFlow::Done => {
                                cache.push(code);
                                break;
                            }
                            ControlFlow::Die => {
                                cache.push(code);
                                maybe_fail_delay(pamh, status);
                                return Ok(PamStatus::new(status));
                            }
                        }
                    }
                    Err(e) => {
                        if !entry.optional_load {
                            return Err(e);
                        }
                    }
                }
            }
            cache.push(PAM_SUCCESS);
            i += 1;
            continue;
        }

        let actions = entry.resolved_actions();
        pamh.current_module = Some(entry.module.clone());

        let retval = match invoke_module(pamh, flags, kind, entry, category, &module_dir) {
            Ok(s) => s.code(),
            Err(e) => {
                if entry.optional_load {
                    PAM_IGNORE
                } else {
                    #[cfg(feature = "std")]
                    crate::log::error(pamh, &alloc::format!("module error: {e}"));
                    e.to_status().code()
                }
            }
        };

        cache.push(retval);
        pamh.current_module = None;

        if retval == PAM_INCOMPLETE {
            return Ok(PamStatus::new(PAM_INCOMPLETE));
        }

        let action = action_for(&actions, retval);
        // requisite: Die on bad is already in actions
        match apply_action(action, retval, &mut impression, &mut status) {
            ControlFlow::Continue => {
                if let Action::Jump(n) = action {
                    i = i.saturating_add(n as usize);
                    continue;
                }
            }
            ControlFlow::Done => break,
            ControlFlow::Die => {
                if kind == StackKind::Auth {
                    pamh.cached_auth_retvals = cache;
                }
                maybe_fail_delay(pamh, status);
                return Ok(PamStatus::new(status));
            }
        }
        i += 1;
    }

    if kind == StackKind::Auth {
        pamh.cached_auth_retvals = cache;
    }

    let final_status = match impression {
        Impression::Positive => {
            if status == PAM_NEW_AUTHTOK_REQD {
                PAM_NEW_AUTHTOK_REQD
            } else {
                PAM_SUCCESS
            }
        }
        Impression::Negative => status,
        Impression::Undef => PAM_PERM_DENIED,
    };

    maybe_fail_delay(pamh, final_status);
    Ok(PamStatus::new(final_status))
}

fn dispatch_entries(
    pamh: &mut PamHandle,
    flags: i32,
    kind: StackKind,
    entries: &[ModuleEntry],
    category: BuildCategory,
    module_dir: &str,
) -> PamResult<PamStatus> {
    let mut impression = Impression::Undef;
    let mut status = PAM_PERM_DENIED;
    for entry in entries {
        if matches!(entry.control, ControlFlag::Include | ControlFlag::Substack) {
            continue;
        }
        let actions = entry.resolved_actions();
        pamh.current_module = Some(entry.module.clone());
        let retval = match invoke_module(pamh, flags, kind, entry, category, module_dir) {
            Ok(s) => s.code(),
            Err(e) => e.to_status().code(),
        };
        pamh.current_module = None;
        let action = action_for(&actions, retval);
        match apply_action(action, retval, &mut impression, &mut status) {
            ControlFlow::Continue => {}
            ControlFlow::Done => break,
            ControlFlow::Die => return Ok(PamStatus::new(status)),
        }
    }
    let final_status = match impression {
        Impression::Positive => PAM_SUCCESS,
        Impression::Negative => status,
        Impression::Undef => PAM_PERM_DENIED,
    };
    Ok(PamStatus::new(final_status))
}

fn invoke_module(
    pamh: &mut PamHandle,
    flags: i32,
    kind: StackKind,
    entry: &ModuleEntry,
    category: BuildCategory,
    module_dir: &str,
) -> PamResult<PamStatus> {
    #[cfg(feature = "std")]
    {
        let hooks = resolve_module(&entry.module, module_dir, category)?;
        let status = hooks.call(kind, pamh, flags, &entry.args);
        Ok(status)
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = (pamh, flags, kind, entry, category, module_dir);
        Err(PamError::Status(PamStatus::new(PAM_SYSTEM_ERR)))
    }
}

fn action_for(actions: &[Action; PAM_RETURN_VALUES], retval: i32) -> Action {
    if retval >= 0 && (retval as usize) < PAM_RETURN_VALUES {
        actions[retval as usize]
    } else {
        Action::Bad
    }
}

enum ControlFlow {
    Continue,
    Done,
    Die,
}

fn apply_action(
    action: Action,
    retval: i32,
    impression: &mut Impression,
    status: &mut i32,
) -> ControlFlow {
    match action {
        Action::Ignore => ControlFlow::Continue,
        Action::Ok => {
            if *impression == Impression::Undef {
                *impression = Impression::Positive;
                *status = retval;
            } else if *impression == Impression::Positive
                && *status == PAM_SUCCESS
                && retval == PAM_NEW_AUTHTOK_REQD
            {
                *status = PAM_NEW_AUTHTOK_REQD;
            }
            ControlFlow::Continue
        }
        Action::Done => {
            if *impression != Impression::Negative {
                *impression = Impression::Positive;
                *status = retval;
                return ControlFlow::Done;
            }
            ControlFlow::Continue
        }
        Action::Bad => {
            if *impression != Impression::Negative {
                *impression = Impression::Negative;
                *status = if retval == PAM_SUCCESS {
                    PAM_PERM_DENIED
                } else {
                    retval
                };
            }
            ControlFlow::Continue
        }
        Action::Die => {
            *impression = Impression::Negative;
            *status = if retval == PAM_SUCCESS {
                PAM_PERM_DENIED
            } else {
                retval
            };
            ControlFlow::Die
        }
        Action::Reset => {
            *impression = Impression::Undef;
            *status = PAM_PERM_DENIED;
            ControlFlow::Continue
        }
        Action::Jump(_) => ControlFlow::Continue,
    }
}

fn maybe_fail_delay(pamh: &mut PamHandle, status: i32) {
    if status == PAM_SUCCESS {
        pamh.fail_delay_usec = 0;
        return;
    }
    #[cfg(all(feature = "std", feature = "fail_delay"))]
    {
        let mut usec = pamh.fail_delay_usec;
        if usec == 0 {
            usec = pamh.global.security.fail_delay_usec;
        }
        if usec > 0 {
            crate::delay::sleep_usec(usec);
        }
        pamh.fail_delay_usec = 0;
    }
    #[cfg(not(all(feature = "std", feature = "fail_delay")))]
    {
        let _ = (pamh, status);
    }
}

/// Unit-test helper: run a synthetic stack without filesystem.
#[cfg(all(test, feature = "std"))]
pub fn dispatch_test_stack(
    pamh: &mut PamHandle,
    flags: i32,
    kind: StackKind,
    entries: &[ModuleEntry],
) -> PamResult<PamStatus> {
    let category = BuildCategory::Standalone;
    dispatch_entries(pamh, flags, kind, entries, category, "")
}
