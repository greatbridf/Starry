#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::{alloc::Layout, cell::UnsafeCell, ptr::NonNull};
use axhal::arch::TaskContext as ThreadStruct;
use axhal::mem::VirtAddr;

pub type Pid = usize;

pub struct SchedInfo {
    pid: Pid,

    /* CPU-specific state of this task: */
    pub thread: UnsafeCell<ThreadStruct>,
}

impl SchedInfo {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            thread: UnsafeCell::new(ThreadStruct::new()),
        }
    }

    pub fn get_pid(&self) -> Pid {
        self.pid
    }

    #[inline]
    pub const unsafe fn ctx_mut_ptr(&self) -> *mut ThreadStruct {
        self.thread.get()
    }

    pub fn reset(&mut self, entry: usize, sp: VirtAddr, v: VirtAddr) {
        self.thread.get_mut().init(entry, sp, v);
    }
}

/// The reference type of a task.
pub type CtxRef = Arc<SchedInfo>;

/// A wrapper of [`TaskCtxRef`] as the current task contex.
pub struct CurrentCtx(ManuallyDrop<CtxRef>);

impl CurrentCtx {
    pub(crate) fn try_get() -> Option<Self> {
        let ptr: *const SchedInfo = axhal::cpu::current_task_ptr();
        if !ptr.is_null() {
            Some(Self(unsafe { ManuallyDrop::new(CtxRef::from_raw(ptr)) }))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current sched info is uninitialized")
    }
}

impl Deref for CurrentCtx {
    type Target = CtxRef;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn current_ctx() -> CurrentCtx {
    CurrentCtx::get()
}

pub fn try_current_ctx() -> Option<CurrentCtx> {
    CurrentCtx::try_get()
}
