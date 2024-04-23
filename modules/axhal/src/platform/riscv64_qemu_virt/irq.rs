//! TODO: PLIC

use riscv::register::sie;

/// `Interrupt` bit in `scause`
pub(super) const INTC_IRQ_BASE: usize = 1 << (usize::BITS - 1);

/// Supervisor software interrupt in `scause`
#[allow(unused)]
pub(super) const S_SOFT: usize = INTC_IRQ_BASE + 1;

/// Supervisor timer interrupt in `scause`
pub(super) const S_TIMER: usize = INTC_IRQ_BASE + 5;

/// Supervisor external interrupt in `scause`
#[allow(unused)]
pub(super) const S_EXT: usize = INTC_IRQ_BASE + 9;

/// The maximum number of IRQs.
#[allow(dead_code)]
pub const MAX_IRQ_COUNT: usize = 1024;

/// The timer IRQ number (supervisor timer interrupt in `scause`).
pub const TIMER_IRQ_NUM: usize = S_TIMER;

pub(super) fn init_percpu() {
    // enable soft interrupts, timer interrupts, and external interrupts
    unsafe {
        sie::set_ssoft();
        sie::set_stimer();
        sie::set_sext();
    }
}
