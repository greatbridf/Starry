#![cfg_attr(not(test), no_std)]

use taskctx::Pid;
use axerrno::LinuxError;
use axconfig::TASK_STACK_SIZE;

#[macro_use]
extern crate log;

const RLIMIT_STACK: usize = 3;  /* max stack size */
//const RLIM_NLIMITS: usize = 16;

struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

impl RLimit64 {
    pub fn new(rlim_cur: u64, rlim_max: u64) -> Self {
        Self {
            rlim_cur,
            rlim_max,
        }
    }
}

pub fn gettid() -> usize {
    taskctx::current_ctx().pid()
}

pub fn getpid() -> usize {
    taskctx::current_ctx().tgid()
}

pub fn prlimit64(
    pid: Pid,
    resource: usize,
    new_rlim: usize,
    old_rlim: usize
) -> usize {
    warn!("linux_syscall_prlimit64: pid {}, resource: {}, {:?} {:?}",
        pid, resource, new_rlim, old_rlim);

    assert!(pid == 0);

    let old_rlim = old_rlim as *mut RLimit64;

    match resource {
        RLIMIT_STACK => {
            let stack_size = TASK_STACK_SIZE as u64;
            axhal::arch::enable_sum();
            unsafe {
                *old_rlim = RLimit64::new(stack_size, stack_size);
            }
            axhal::arch::disable_sum();
            0
        },
        _ => {
            unimplemented!("Resource Type: {}", resource);
        }
    }
}
