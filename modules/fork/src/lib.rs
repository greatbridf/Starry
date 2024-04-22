#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;

use axerrno::{LinuxError, LinuxResult};
use task::{current, Pid, TaskRef};

bitflags::bitflags! {
    /// clone flags
    pub struct CloneFlags: usize {
        /// signal mask to be sent at exit
        const CSIGNAL       = 0x000000ff;
        /// set if VM shared between processes
        const CLONE_VM      = 0x00000100;
        /// set if fs info shared between processes
        const CLONE_FS      = 0x00000200;
        /// set if open files shared between processes
        const CLONE_FILES   = 0x00000400;
        /// set if signal handlers and blocked signals shared
        const CLONE_SIGHAND = 0x00000800;
        /// set if the tracing process can't force CLONE_PTRACE on this clone
        const CLONE_UNTRACED= 0x00800000;
    }
}

struct KernelCloneArgs {
    flags: CloneFlags,
    _name: String,
    _exit_signal: u32,
    entry: Option<*mut dyn FnOnce()>,
}

impl KernelCloneArgs {
    fn new(
        flags: CloneFlags,
        name: &str,
        exit_signal: u32,
        entry: Option<*mut dyn FnOnce()>,
    ) -> Self {
        Self {
            flags,
            _name: String::from(name),
            _exit_signal: exit_signal,
            entry,
        }
    }

    /// The main fork-routine, as kernel_clone in linux kernel.
    ///
    /// It copies the process, and if successful kick-starts it and
    /// waits for it to finish using the VM if required.
    /// The arg *exit_signal* is expected to be checked for sanity
    /// by the caller.
    fn perform(&self) -> LinuxResult<Pid> {
        let trace = !self.flags.contains(CloneFlags::CLONE_UNTRACED);
        // Todo: ptrace
        assert!(!trace);

        let task = self.copy_process(None, trace)?;
        debug!(
            "sched task fork: pid[{}] -> pid[{}].",
            task::current().pid(),
            task.pid()
        );

        let pid = task.pid();
        self.wake_up_new_task(task);
        Ok(pid)
    }

    /// Wake up a newly created task for the first time.
    ///
    /// This function will do some initial scheduler statistics housekeeping
    /// that must be done for every newly created context, then puts the task
    /// on the runqueue and wakes it.
    fn wake_up_new_task(&self, task: TaskRef) {
        let rq = run_queue::task_rq(&task.sched_info);
        rq.lock().activate_task(task.sched_info.clone());
        debug!("wakeup the new task[{}].", task.pid());
    }

    fn copy_process(&self, _pid: Option<Pid>, trace: bool) -> LinuxResult<TaskRef> {
        info!("copy_process...");
        assert!(!trace);
        let mut task = current().dup_task_struct();
        //copy_files();
        self.copy_fs(&mut task)?;
        //copy_sighand();
        //copy_signal();
        //copy_mm();
        self.copy_thread(task.clone());
        Ok(task)
    }

    fn copy_fs(&self, task: &mut TaskRef) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_FS) {
            /* task.fs is already what we want */
            let fs = task::current().fs.clone();
            let mut locked_fs = fs.lock();
            if locked_fs.in_exec {
                return Err(LinuxError::EAGAIN);
            }
            locked_fs.users += 1;
            return Ok(());
        }
        task.fs.lock().copy_fs_struct(task::current().fs.clone());
        Ok(())
    }

    fn copy_thread(&self, task: TaskRef) {
        info!("copy_thread ...");
        assert!(self.entry.is_some());
        use alloc::sync::Arc;
        let task = task::as_task_mut(task);
        Arc::get_mut(&mut task.sched_info).unwrap().reset(
            self.entry,
            task_entry as usize,
            0.into(),
        );
        error!("copy_thread!");
    }
}

// Todo: We should move task_entry to taskctx.
// Now schedule_tail: 'run_queue::force_unlock();` hinders us.
// Consider to move it to sched first!
extern "C" fn task_entry() -> ! {
    // schedule_tail
    // unlock runqueue for freshly created task
    run_queue::force_unlock();

    let task = crate::current();
    if let Some(entry) = task.sched_info.entry {
        unsafe { Box::from_raw(entry)() };
    }

    let sp = task::current().pt_regs();
    axhal::arch::ret_from_fork(sp);
    unimplemented!("task_entry!");
}

/// Create a user mode thread.
///
/// Invoke `f` to do some preparations before entering userland.
pub fn user_mode_thread<F>(f: F, flags: CloneFlags) -> Pid
where
    F: FnOnce() + 'static,
{
    info!("create a user mode thread ...");
    assert!((flags.bits() & CloneFlags::CSIGNAL.bits()) == 0);
    let f = Box::into_raw(Box::new(f));
    let args = KernelCloneArgs::new(
        flags | CloneFlags::CLONE_VM | CloneFlags::CLONE_UNTRACED,
        "",
        0,
        Some(f),
    );
    args.perform().expect("kernel_clone failed.")
}
