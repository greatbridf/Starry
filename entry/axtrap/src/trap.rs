pub fn handle_irq(_irq_num: usize, _from_user: bool) {
    #[cfg(feature = "irq")]
    {
        let guard = kernel_guard::NoPreempt::new();
        // trap进来，统计时间信息
        // 只有当trap是来自用户态才进行统计
        #[cfg(feature = "monolithic")]
        linux_syscall_api::trap::handle_irq(_irq_num, _from_user);

        #[cfg(not(feature = "monolithic"))]
        axhal::irq::dispatch_irq(_irq_num);
        drop(guard); // rescheduling may occur when preemption is re-enabled.

        #[cfg(feature = "preempt")]
        axtask::current_check_preempt_pending();
    }
}

#[cfg(feature = "monolithic")]
pub(crate) fn handle_syscall(syscall_id: usize, args: [usize; 6]) -> isize {
    let ans = linux_syscall_api::trap::handle_syscall(syscall_id, args);
    ans
}
#[cfg(feature = "monolithic")]
pub(crate) fn handle_page_fault(
    addr: linux_syscall_api::trap::VirtAddr,
    flags: linux_syscall_api::trap::MappingFlags,
) {
    linux_syscall_api::trap::handle_page_fault(addr, flags);
}
#[cfg(feature = "monolithic")]
pub(crate) fn handle_signal() {
    linux_syscall_api::trap::handle_signals();
}
#[cfg(feature = "monolithic")]
pub(crate) fn record_trap(syscall_code: usize) {
    linux_syscall_api::trap::record_trap(syscall_code);
}
