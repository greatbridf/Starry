use core::arch::global_asm;

use axsyscall::SyscallArgs;
use x86_64::{
    registers::{
        model_specific::{Efer, EferFlags, LStar, SFMask, Star},
        rflags::RFlags,
    },
    VirtAddr,
};

use axhal::arch::GdtStruct;

use super::TrapFrame;

global_asm!(include_str!("syscall.S"));

pub fn init_syscall() {
    extern "C" {
        fn syscall_entry();
    }
    LStar::write(VirtAddr::new(syscall_entry as usize as _));
    Star::write(
        GdtStruct::UCODE64_SELECTOR,
        GdtStruct::UDATA_SELECTOR,
        GdtStruct::KCODE64_SELECTOR,
        GdtStruct::KDATA_SELECTOR,
    )
    .unwrap();
    SFMask::write(
        RFlags::TRAP_FLAG
            | RFlags::INTERRUPT_FLAG
            | RFlags::DIRECTION_FLAG
            | RFlags::IOPL_LOW
            | RFlags::IOPL_HIGH
            | RFlags::NESTED_TASK
            | RFlags::ALIGNMENT_CHECK,
    ); // TF | IF | DF | IOPL | AC | NT (0x47700)
    unsafe {
        Efer::update(|efer| *efer |= EferFlags::SYSTEM_CALL_EXTENSIONS);
    }
}

#[no_mangle]
fn x86_syscall_handler(tf: &mut TrapFrame) {
    debug!("handle_linux_syscall");
    syscall(tf, axsyscall::do_syscall);
}
fn syscall_args(tf: &TrapFrame) -> SyscallArgs {
    [tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9].map(|n| n as _)
}

fn syscall<F>(tf: &mut TrapFrame, do_syscall: F)
where
    F: FnOnce(SyscallArgs, usize) -> usize,
{
    error!("Syscall: {:#x}, {}", tf.rax, tf.rax);
    let args = syscall_args(tf);
    tf.rax = do_syscall(args, tf.rax as usize) as u64;
}
