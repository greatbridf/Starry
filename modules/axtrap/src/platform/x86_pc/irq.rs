#![allow(dead_code)]

/// Enables or disables the given IRQ.
#[cfg(feature = "irq")]
pub fn set_enable(vector: usize, enabled: bool) {
    axhal::x86_64::set_enable(vector, enabled)
}

/// Registers an IRQ handler for the given IRQ.
///
/// It also enables the IRQ if the registration succeeds. It returns `false` if
/// the registration failed.
#[cfg(feature = "irq")]
pub fn register_handler(vector: usize, handler: crate::irq::IrqHandler) -> bool {
    crate::irq::register_handler_common(vector, handler)
}

/// Dispatches the IRQ.
///
/// This function is called by the common interrupt handler. It looks
/// up in the IRQ handler table and calls the corresponding handler. If
/// necessary, it also acknowledges the interrupt controller after handling.
#[cfg(feature = "irq")]
pub fn dispatch_irq(vector: usize) {
    crate::irq::dispatch_irq_common(vector);
    axhal::x86_64::end_of_interrupt();
}
