//! Interrupt management.

use handler_table::HandlerTable;

use crate::platform::irq::MAX_IRQ_COUNT;

/// The type if an IRQ handler.
pub type IrqHandler = handler_table::Handler;
