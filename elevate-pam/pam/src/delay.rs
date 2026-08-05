//! Fail-delay timing (authentication side-channel mitigation).

/// Sleep for approximately `usec` microseconds.
pub fn sleep_usec(usec: u32) {
    if usec == 0 {
        return;
    }
    let secs = (usec / 1_000_000) as u64;
    let nanos = ((usec % 1_000_000) * 1000) as u32;
    std::thread::sleep(std::time::Duration::new(secs, nanos));
}
