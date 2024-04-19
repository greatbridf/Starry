pub use axhal::{mem::VirtAddr, paging::MappingFlags};

use crate::syscall::syscall;

pub fn time_stat_from_kernel_to_user() {
    axprocess::time_stat_from_kernel_to_user();
}

pub fn time_stat_from_user_to_kernel() {
    axprocess::time_stat_from_user_to_kernel();
}

pub fn handle_irq(irq_num: usize, from_user: bool) {
    // trap进来，统计时间信息
    // 只有当trap是来自用户态才进行统计
    if from_user {
        time_stat_from_user_to_kernel();
    }
    axhal::irq::dispatch_irq(irq_num);
    if from_user {
        time_stat_from_kernel_to_user();
    }
}

pub fn handle_syscall(syscall_id: usize, args: [usize; 6]) -> isize {
    time_stat_from_user_to_kernel();
    let ans = syscall(syscall_id, args);
    time_stat_from_kernel_to_user();
    ans
}

pub fn handle_page_fault(addr: VirtAddr, flags: MappingFlags) {
    time_stat_from_user_to_kernel();
    axprocess::handle_page_fault(addr, flags);
    time_stat_from_kernel_to_user();
}

pub fn handle_signals() {
    time_stat_from_user_to_kernel();
    axprocess::signal::handle_signals();
    time_stat_from_kernel_to_user();
}

pub fn record_trap(syscall_code: usize) {
    axfs::axfs_ramfs::INTERRUPT.lock().record(syscall_code);
}
