#[macro_use]
mod macros;

use axhal::arch::TrapFrame;

use riscv::register::scause::{self, Exception as E, Trap};
use riscv::register::{stval, stvec};

#[cfg(not(feature = "monolithic"))]
use axruntime::trap::*;
#[cfg(feature = "monolithic")]
use linux_syscall_api::trap::*;

include_trap_asm_marcos!();
core::arch::global_asm!(
    include_str!("trap.S"),
    trapframe_size = const core::mem::size_of::<TrapFrame>(),
);

/// Writes Supervisor Trap Vector Base Address Register (`stvec`).
#[inline]
pub fn set_trap_vector_base(stvec: usize) {
    unsafe { stvec::write(stvec, stvec::TrapMode::Direct) }
}

extern "C" {
    fn trap_vector_base();
}

pub fn init_trap_vector_base() {
    set_trap_vector_base(trap_vector_base as usize);
}

fn handle_breakpoint(sepc: &mut usize) {
    axlog::debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}

#[no_mangle]
pub fn riscv_trap_handler(tf: &mut TrapFrame, from_user: bool) {
    let scause = scause::read();

    match scause.cause() {
        Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.sepc),
        Trap::Interrupt(_) => handle_irq(scause.bits(), from_user),

        #[cfg(feature = "monolithic")]
        Trap::Exception(E::UserEnvCall) => {
            axhal::arch::enable_irqs();
            tf.sepc += 4;
            let result = handle_syscall(
                tf.regs.a7,
                [
                    tf.regs.a0, tf.regs.a1, tf.regs.a2, tf.regs.a3, tf.regs.a4, tf.regs.a5,
                ],
            );
            tf.regs.a0 = result as usize;
        }

        #[cfg(feature = "monolithic")]
        Trap::Exception(E::InstructionPageFault) => {
            let addr = stval::read();
            if !from_user {
                unimplemented!(
                    "I page fault from kernel, addr: {:X}, sepc: {:X}",
                    addr,
                    tf.sepc
                );
            }
            handle_page_fault(addr.into(), MappingFlags::USER | MappingFlags::EXECUTE);
        }

        #[cfg(feature = "monolithic")]
        Trap::Exception(E::LoadPageFault) => {
            let addr = stval::read();
            if !from_user {
                unimplemented!(
                    "L page fault from kernel, addr: {:X}, sepc: {:X}",
                    addr,
                    tf.sepc
                );
            }
            handle_page_fault(addr.into(), MappingFlags::USER | MappingFlags::READ);
        }

        #[cfg(feature = "monolithic")]
        Trap::Exception(E::StorePageFault) => {
            let addr = stval::read();
            if !from_user {
                unimplemented!(
                    "S page fault from kernel, addr: {:X}, sepc: {:X}",
                    addr,
                    tf.sepc
                );
            }

            handle_page_fault(addr.into(), MappingFlags::USER | MappingFlags::WRITE);
        }

        _ => {
            panic!(
                "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                scause.cause(),
                tf.sepc,
                tf
            );
        }
    }

    #[cfg(feature = "monolithic")]
    {
        if from_user {
            handle_signal();
        }
        // 在保证将寄存器都存储好之后，再开启中断
        // 否则此时会因为写入csr寄存器过程中出现中断，导致出现异常
        axhal::arch::disable_irqs();
    }
}
