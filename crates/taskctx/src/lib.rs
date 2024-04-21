#![no_std]
#![feature(naked_functions)]
#![feature(asm_const)]

mod arch;
mod current;
pub use current::*;

pub use arch::*;
#[cfg(feature = "tls")]
mod tls;

mod stat;
pub use stat::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "multitask")] {
        mod kstack;
        use kstack::*;mod task;
        pub use task::*;

    }
}

#[cfg(feature = "preempt")]
pub fn disable_preempt() {
    let ptr: *const TaskInner = current_task_ptr();
    if !ptr.is_null() {
        unsafe {
            (*ptr).disable_preempt();
        }
    }
}

#[cfg(feature = "preempt")]
pub fn enable_preempt() {
    let ptr: *const TaskInner = current_task_ptr();
    if !ptr.is_null() {
        unsafe {
            (*ptr).enable_preempt();
        }
    }
}
