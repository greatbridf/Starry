use core::ffi::{c_char, c_int};

use axerrno::LinuxError;
use axfs::api::set_current_dir;

use crate::utils::char_ptr_to_str;

/// Relinquish the CPU, and switches to another task.
///
/// For single-threaded configuration (`multitask` feature is disabled), we just
/// relax the CPU and wait for incoming interrupts.
pub fn sys_sched_yield() -> c_int {
    #[cfg(feature = "multitask")]
    axtask::yield_now();
    #[cfg(not(feature = "multitask"))]
    if cfg!(feature = "irq") {
        axhal::arch::wait_for_irqs();
    } else {
        core::hint::spin_loop();
    }
    0
}

/// Get current thread ID.
pub fn sys_getpid() -> c_int {
    syscall_body!(sys_getpid,
        #[cfg(feature = "multitask")]
        {
            Ok(axtask::current().id().as_u64() as c_int)
        }
        #[cfg(not(feature = "multitask"))]
        {
            Ok(2) // `main` task ID
        }
    )
}

/// Exit current task
pub fn sys_exit(exit_code: c_int) -> ! {
    debug!("sys_exit <= {}", exit_code);
    #[cfg(feature = "multitask")]
    axtask::exit(exit_code);
    #[cfg(not(feature = "multitask"))]
    axhal::misc::terminate();
}

/// Set working path of the current task
pub fn sys_chdir(pathname: *const c_char) -> i32 {
    // TODO: The current implementation is PROBLEMATIC!!!
    //       The namespaces are not isolated AT ALL.
    //       All the threads share the same CURRENT_DIR and CURRENT_DIR_PATH variables.
    syscall_body!(sys_chdir, {
        let pathname = char_ptr_to_str(pathname)?;
        set_current_dir(pathname)
            .map(|_| 0)
            .map_err(LinuxError::from)
    })
}
