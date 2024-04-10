#![no_std]

use taskctx::CtxRef;
use crate::run_queue::RUN_QUEUE;
use spinlock::SpinNoIrq;

#[macro_use]
extern crate log;
extern crate alloc;
mod run_queue;
pub use run_queue::AxRunQueue;

pub fn init() {
    RUN_QUEUE.init_by(AxRunQueue::new());
}

pub fn task_rq(_task: &CtxRef) -> &SpinNoIrq<AxRunQueue> {
    &RUN_QUEUE
}

pub fn force_unlock() {
    unsafe { RUN_QUEUE.force_unlock() }
}

/// Handles periodic timer ticks for the task manager.
///
/// For example, advance scheduler states, checks timed events, etc.
pub fn on_timer_tick() {
    RUN_QUEUE.lock().scheduler_timer_tick();
}
