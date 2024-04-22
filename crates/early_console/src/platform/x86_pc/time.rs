static mut INIT_TICK: u64 = 0;
static mut CPU_FREQ_MHZ: u64 = axconfig::TIMER_FREQUENCY as u64 / 1_000_000;

/// Returns the current clock time in hardware ticks.
pub fn current_ticks() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() - INIT_TICK }
}

/// Converts hardware ticks to nanoseconds.
pub fn ticks_to_nanos(ticks: u64) -> u64 {
    ticks * 1_000 / unsafe { CPU_FREQ_MHZ }
}
