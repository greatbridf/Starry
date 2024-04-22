mod apic;
pub use apic::{end_of_interrupt, set_enable};
pub mod dtables;
pub use dtables::set_tss_stack_top;

pub mod mem;
pub mod misc;
pub mod time;

#[cfg(feature = "smp")]
pub mod mp;

#[cfg(feature = "irq")]
pub mod irq {
    pub use super::apic::*;
}

// replace it with early_console
// pub mod console {
//     pub use super::uart16550::*;
// }

/// Initializes the platform devices for the primary CPU.
pub fn platform_init() {
    self::apic::init_primary();
    self::time::init_primary();
}

/// Initializes the platform devices for secondary CPUs.
#[cfg(feature = "smp")]
pub fn platform_init_secondary() {
    self::apic::init_secondary();
    self::time::init_secondary();
}
