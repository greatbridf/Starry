use crate::trap::TRAPFRAME_SIZE;

include_asm_marcos!();

pub fn ret_from_fork(kstack_sp: usize) {
    let tramframe_size = core::mem::sizeof::<TrapFrame>();

    unsafe {
        core::arch::asm!(
            r"
            mv  sp, {kstack_sp}
            addi t0, sp, {tramframe_size}
            csrw sscratch, t0
            RESTORE_REGS 1
            sret
            ",
            kstack_sp = in(reg) kstack_sp,
            tramframe_size = in(reg) tramframe_size,
        );
    };
}
