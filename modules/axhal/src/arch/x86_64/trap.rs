use memory_addr::VirtAddr;
use x86_64::registers::model_specific::KernelGsBase;

use super::TrapFrame;

#[no_mangle]
#[percpu2::def_percpu]
static USER_RSP_OFFSET: usize = 0;

#[no_mangle]
#[percpu2::def_percpu]
static KERNEL_RSP_OFFSET: usize = 0;

pub fn ret_from_fork(kstack_sp: usize) {
    // The kstack has pushed the trap frame, so the kstack sp is the top of the trap frame.
    KernelGsBase::write(x86_64::VirtAddr::new(0));
    let trap_frame_size = core::mem::size_of::<TrapFrame>();
    let kstack_base = kstack_sp + trap_frame_size;
    crate::platform::set_tss_stack_top(VirtAddr::from(kstack_base));
    unsafe {
        core::arch::asm!(
            r"
                    mov     gs:[offset __PERCPU_KERNEL_RSP_OFFSET], {kstack_base}

                    mov      rsp, {kstack_sp}

                    pop rax
                    pop rcx
                    pop rdx
                    pop rbx
                    pop rbp
                    pop rsi
                    pop rdi
                    pop r8
                    pop r9
                    pop r10
                    pop r11
                    pop r12
                    pop r13
                    pop r14
                    pop r15
                    add rsp, 16

                    swapgs
                    iretq
                ",
            kstack_sp = in(reg) kstack_sp,
            kstack_base = in(reg) kstack_base,
        );
    };
}
