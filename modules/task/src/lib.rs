#![no_std]
#![feature(get_mut_unchecked)]
#![feature(const_trait_impl)]
#![feature(effects)]

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicUsize, Ordering};

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;

use axhal::arch::TaskContext as ThreadStruct;
use mm::MmStruct;
use mm::switch_mm;
use spinlock::SpinNoIrq;
use fstree::FsStruct;
use filetable::FileTable;
use crate::tid_map::{register_task, get_task};
use taskctx::SchedInfo;
pub use taskctx::Pid;
pub use taskctx::current_ctx;
pub use taskctx::{TaskStack, THREAD_SIZE};

mod tid_map;

static NEXT_PID: AtomicUsize = AtomicUsize::new(0);

pub struct TaskStruct {
    mm: Option<Arc<SpinNoIrq<MmStruct>>>,
    pub active_mm_id: AtomicUsize,
    pub fs: Arc<SpinNoIrq<FsStruct>>,
    pub filetable: Arc<SpinNoIrq<FileTable>>,

    pub sched_info: Arc<SchedInfo>,
}

unsafe impl Send for TaskStruct {}
unsafe impl Sync for TaskStruct {}

impl TaskStruct {
    pub fn new() -> Arc<Self> {
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        warn!("\n++++++++++++++++++++++++++++++++++++++ TaskStruct::new pid {}\n", pid);
        let arc = Arc::new(Self {
            mm: None,
            active_mm_id: AtomicUsize::new(0),
            fs: Arc::new(SpinNoIrq::new(FsStruct::new())),
            filetable: Arc::new(SpinNoIrq::new(FileTable::new())),

            sched_info: Arc::new(SchedInfo::new(pid)),
        });
        register_task(pid, arc.clone());
        arc
    }

    pub fn pid(&self) -> Pid {
        self.sched_info.pid()
    }

    pub fn tgid(&self) -> usize {
        self.sched_info.tgid()
    }

    pub fn pt_regs(&self) -> usize {
        self.sched_info.pt_regs()
    }

    pub fn try_mm(&self) -> Option<Arc<SpinNoIrq<MmStruct>>> {
        self.mm.as_ref().and_then(|mm| Some(mm.clone()))
    }

    pub fn mm(&self) -> Arc<SpinNoIrq<MmStruct>> {
        self.mm.as_ref().expect("NOT a user process.").clone()
    }

    pub fn alloc_mm(&mut self) {
        error!("alloc_mm...");
        assert!(self.mm.is_none());
        self.mm.replace(Arc::new(SpinNoIrq::new(MmStruct::new())));
        switch_mm(0, self.mm());
    }

    pub fn dup_task_struct(&self) -> Arc<Self> {
        info!("dup_task_struct ...");
        ///////////////////////
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        let task = Arc::new(Self {
            mm: None,
            active_mm_id: AtomicUsize::new(0),
            fs: self.fs.clone(),
            filetable: Arc::new(SpinNoIrq::new(FileTable::new())),

            sched_info: self.sched_info.dup_sched_info(pid),
        });
        register_task(pid, task.clone());
        ///////////////////////
        task
    }

    #[inline]
    pub const unsafe fn ctx_mut_ptr(&self) -> *mut ThreadStruct {
        self.sched_info.ctx_mut_ptr()
    }
}

// Todo: It is unsafe extremely. We must remove it!!!
// Now it's just for fork.copy_process.
// In fact, we can prepare everything and then init task in the end.
// At that time, we can remove as_task_mut.
pub fn as_task_mut(task: TaskRef) -> &'static mut TaskStruct {
    unsafe {
        &mut (*(Arc::as_ptr(&task) as *mut TaskStruct))
    }
}

/// The reference type of a task.
pub type TaskRef = Arc<TaskStruct>;

/// A wrapper of [`TaskRef`] as the current task.
pub struct CurrentTask(ManuallyDrop<TaskRef>);

impl CurrentTask {
    pub(crate) fn try_get() -> Option<Self> {
        if let Some(ctx) = taskctx::try_current_ctx() {
            let pid = ctx.pid();
            let task = get_task(pid).expect("try_get None");
            Some(Self(ManuallyDrop::new(task)))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current task is uninitialized")
    }

    pub fn ptr_eq(&self, other: &TaskRef) -> bool {
        Arc::ptr_eq(&self, other)
    }

    /// Converts [`CurrentTask`] to [`TaskRef`].
    pub fn as_task_ref(&self) -> &TaskRef {
        &self.0
    }

    pub fn as_task_mut(&mut self) -> &mut TaskStruct {
        unsafe {
            Arc::get_mut_unchecked(&mut self.0)
        }
    }

    pub(crate) unsafe fn init_current(init_task: TaskRef) {
        error!("CurrentTask::init_current...");
        let ptr = Arc::into_raw(init_task.sched_info.clone());
        axhal::cpu::set_current_task_ptr(ptr);
    }

    pub unsafe fn set_current(prev: Self, next: TaskRef) {
        error!("CurrentTask::set_current...");
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next.sched_info.clone());
        axhal::cpu::set_current_task_ptr(ptr);
    }
}

impl Deref for CurrentTask {
    type Target = TaskRef;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Gets the current task.
///
/// # Panics
///
/// Panics if the current task is not initialized.
pub fn current() -> CurrentTask {
    CurrentTask::get()
}

/// Current task gives up the CPU time voluntarily, and switches to another
/// ready task.
pub fn yield_now() {
    unimplemented!("yield_now");
}

/// Exits the current task.
pub fn exit(exit_code: i32) -> ! {
    unimplemented!("exit {}", exit_code);
}

pub fn init() {
    error!("task::init ...");
    let init_task = TaskStruct::new();
    //init_task.set_state(TaskState::Running);
    unsafe { CurrentTask::init_current(init_task) }
}
