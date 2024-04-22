#![no_std]

mod platform;
mod time;

pub use platform::{getchar, putchar};

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    platform::console_init();
}

/// Write a slice of bytes to the console.
pub fn write_bytes(bytes: &[u8]) {
    for c in bytes {
        platform::putchar(*c);
    }
}

pub fn time() -> core::time::Duration {
    time::current_time()
}

pub fn cpu_id() -> Option<usize> {
    None
}

pub fn task_id() -> Option<u64> {
    None
}
