//! Module-private data store (`pam_set_data` / `pam_get_data`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::boxed::Box;

/// Cleanup callback signature (mirrors Linux-PAM).
pub type DataCleanup = Option<fn(*mut core::ffi::c_void, i32)>;

/// One module data slot.
struct DataEntry {
    ptr: *mut core::ffi::c_void,
    cleanup: DataCleanup,
}

// SAFETY: DataEntry is only manipulated through PamHandle which is !Send by default
// for the opaque C handle path; Rust API uses single-threaded session model.
unsafe impl Send for DataEntry {}

/// Named data table attached to a PAM handle.
#[derive(Default)]
pub struct DataTable {
    map: BTreeMap<String, DataEntry>,
}

impl DataTable {
    /// Create empty table.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Insert or replace data. Runs previous cleanup with `PAM_DATA_REPLACE` if present.
    pub fn set(
        &mut self,
        name: &str,
        data: *mut core::ffi::c_void,
        cleanup: DataCleanup,
        replace_status: i32,
    ) {
        if let Some(old) = self.map.remove(name) {
            if let Some(cb) = old.cleanup {
                cb(old.ptr, replace_status);
            }
        }
        self.map.insert(
            String::from(name),
            DataEntry {
                ptr: data,
                cleanup,
            },
        );
    }

    /// Get data pointer by name.
    pub fn get(&self, name: &str) -> Option<*mut core::ffi::c_void> {
        self.map.get(name).map(|e| e.ptr)
    }

    /// Drop all entries, invoking cleanups with `status`.
    pub fn clear_with_status(&mut self, status: i32) {
        let map = core::mem::take(&mut self.map);
        for (_k, e) in map {
            if let Some(cb) = e.cleanup {
                cb(e.ptr, status);
            }
        }
    }
}

impl Drop for DataTable {
    fn drop(&mut self) {
        self.clear_with_status(crate::constants::PAM_SUCCESS);
    }
}



/// Box a Rust value into a raw pointer for pam_set_data.
pub fn box_data<T>(value: T) -> *mut core::ffi::c_void {
    Box::into_raw(Box::new(value)) as *mut core::ffi::c_void
}

/// Free boxed data from pam cleanup.
///
/// # Safety
/// `ptr` must have been created by [`box_data`] with the same `T`.
pub unsafe fn free_boxed_data<T>(ptr: *mut core::ffi::c_void) {
    if !ptr.is_null() {
        // SAFETY: caller guarantees ptr came from box_data::<T>
        let _ = unsafe { Box::from_raw(ptr as *mut T) };
    }
}
