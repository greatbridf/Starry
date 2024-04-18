//! Time-related operations.

pub use core::time::Duration;

/// A measurement of the system clock.
///
/// Currently, it reuses the [`core::time::Duration`] type. But it does not
/// represent a duration, but a clock time.
pub type TimeValue = Duration;

#[cfg(feature = "irq")]
pub use crate::platform::irq::TIMER_IRQ_NUM;
#[cfg(feature = "irq")]
pub use crate::platform::time::set_oneshot_timer;
pub use crate::platform::time::{current_ticks, ticks_to_nanos};

/// Number of nanoseconds in a second.
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Returns the current clock time in nanoseconds.
pub fn current_time_nanos() -> u64 {
    ticks_to_nanos(current_ticks())
}

/// Returns the current clock time in [`TimeValue`].
pub fn current_time() -> TimeValue {
    TimeValue::from_nanos(current_time_nanos())
}
