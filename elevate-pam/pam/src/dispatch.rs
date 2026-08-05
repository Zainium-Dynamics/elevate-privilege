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

/// Recursively splice `include` entries' referenced stacks in place,
/// matching upstream `_pam_dispatch_aux`'s "as if written directly here"
/// semantics: an included `sufficient` line can short-circuit the *whole*
/// outer stack, because after this resolution it genuinely *is* part of
/// the outer stack, not a separate isolated sub-evaluation.
///
/// `substack` entries are deliberately left unresolved here -- unlike
/// `include`, a substack's `done`/`die`/`requisite`-failure is confined to
/// the substack itself and its overall pass/fail folds into the parent
/// stack as a single outcome, which is what the isolated
/// `dispatch_entries` call in the main loop already does correctly.
#[cfg(feature = "std")]
fn resolve_includes(
    global: &crate::config::GlobalConfig,
    entries: &[ModuleEntry],
    kind: StackKind,
    depth: u32,
) -> PamResult<Vec<ModuleEntry>> {
    let max_depth = global.security.max_include_depth;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.control != ControlFlag::Include {
            out.push(entry.clone());
            continue;
        }
        if depth >= max_depth {
            if entry.optional_load {
                continue;
            }
            return Err(crate::error::PamError::Config(alloc::format!(
                "include depth exceeded ({max_depth}) resolving '{}'",
                entry.module
            )));
        }
        match crate::config::ServiceConfig::load_service(global, &entry.module) {
            Ok(nested) => {
                let nested_entries = nested.stack_for(kind).to_vec();
                let resolved = resolve_includes(global, &nested_entries, kind, depth + 1)?;
                out.extend(resolved);
            }
            Err(e) => {
                if !entry.optional_load {
                    return Err(e);
                }
            }
        }
    }
    Ok(out)
}

/// Dispatch the configured stack for `kind`.
pub fn dispatch(pamh: &mut PamHandle, flags: i32, kind: StackKind) -> PamResult<PamStatus> {
    let raw_entries: Vec<ModuleEntry> = pamh.service.stack_for(kind).to_vec();
    #[cfg(feature = "std")]
    let entries = resolve_includes(&pamh.global, &raw_entries, kind, 0)?;
    #[cfg(not(feature = "std"))]
    let entries = raw_entries;
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

        // substack: dispatch the nested service's stack in isolation (its own
        // impression/status accumulator) and fold the single outcome into
        // this stack with required-like semantics. `include` no longer
        // reaches this point -- resolve_includes() already spliced it
        // directly into `entries` above, so an included `sufficient` (etc.)
        // participates in *this* loop's own impression/status directly,
        // matching upstream's "as if written here" semantics.
        if entry.control == ControlFlag::Substack {
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::config::GlobalConfig;

    fn entry(control: ControlFlag, module: &str) -> ModuleEntry {
        ModuleEntry {
            control,
            module: module.to_string(),
            args: Vec::new(),
            optional_load: false,
            actions: None,
        }
    }

    fn global_with_services_dir(dir: &std::path::Path) -> GlobalConfig {
        let mut global = GlobalConfig::default();
        global.paths.services_dir = dir.to_string_lossy().into_owned();
        global
    }

    #[test]
    fn resolve_includes_splices_nested_entries_in_place() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("common-auth.toml"),
            r#"
[service]
name = "common-auth"

[[auth]]
control = "sufficient"
module = "permit"
"#,
        )
        .unwrap();

        let global = global_with_services_dir(dir.path());
        let entries = vec![
            entry(ControlFlag::Include, "common-auth"),
            entry(ControlFlag::Required, "deny"),
        ];

        let resolved = resolve_includes(&global, &entries, StackKind::Auth, 0).unwrap();

        // The include is replaced in place by its referenced stack's own
        // entries, with their own control flags intact (not forced to
        // Required) -- not folded into a single opaque outcome.
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].control, ControlFlag::Sufficient);
        assert_eq!(resolved[0].module, "permit");
        assert_eq!(resolved[1].control, ControlFlag::Required);
        assert_eq!(resolved[1].module, "deny");
    }

    #[test]
    fn resolve_includes_depth_limit_errors_when_not_optional() {
        let global = GlobalConfig::default(); // max_include_depth defaults to 32
        let entries = vec![entry(ControlFlag::Include, "whatever")];
        let result = resolve_includes(&global, &entries, StackKind::Auth, 32);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_includes_depth_limit_skips_when_optional() {
        let global = GlobalConfig::default();
        let mut e = entry(ControlFlag::Include, "whatever");
        e.optional_load = true;
        let result = resolve_includes(&global, &[e], StackKind::Auth, 32).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn included_sufficient_short_circuits_the_whole_outer_stack() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("common-auth.toml"),
            r#"
[service]
name = "common-auth"

[[auth]]
control = "sufficient"
module = "permit"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("test.toml"),
            r#"
[service]
name = "test"

[[auth]]
control = "include"
module = "common-auth"

[[auth]]
control = "required"
module = "deny"
"#,
        )
        .unwrap();

        let global = global_with_services_dir(dir.path());
        let mut pamh = crate::appl::PamBuilder::new("test")
            .global(global)
            .start(crate::conv::PamConv::default())
            .unwrap();

        // If the include were still folded into an isolated,
        // required-semantics sub-evaluation (the pre-fix behavior), its
        // success wouldn't stop the outer stack, and the unconditional
        // `deny` right after it would flip the whole result to failure.
        // With real splicing, the included `sufficient` success is
        // evaluated directly against the outer stack and short-circuits
        // it -- `deny` is never reached.
        assert!(pamh.authenticate(0).is_ok());
    }
}
