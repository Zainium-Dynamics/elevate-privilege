//! Item get/set helpers for [`crate::handle::PamHandle`].

use crate::constants::*;
use crate::error::{PamError, PamResult, PamStatus};
use crate::types::ItemType;

/// Validate item type for application callers.
pub fn validate_app_item(item_type: i32) -> PamResult<ItemType> {
    ItemType::from_raw(item_type).ok_or_else(|| PamError::Status(PamStatus::new(PAM_BAD_ITEM)))
}

/// Whether the item is a string item.
pub fn is_string_item(item: ItemType) -> bool {
    matches!(
        item,
        ItemType::Service
            | ItemType::User
            | ItemType::Tty
            | ItemType::RHost
            | ItemType::AuthTok
            | ItemType::OldAuthTok
            | ItemType::RUser
            | ItemType::UserPrompt
            | ItemType::XDisplay
            | ItemType::AuthTokType
    )
}

/// Items that applications must not set directly (module-only) — Linux-PAM rules.
pub fn app_may_set(item: ItemType) -> bool {
    !matches!(item, ItemType::AuthTok | ItemType::OldAuthTok)
}
