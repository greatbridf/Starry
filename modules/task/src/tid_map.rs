use alloc::collections::BTreeMap;
use spinpreempt::SpinLock;
use crate::TaskRef;
use crate::Pid;

static TID_MAP: SpinLock<BTreeMap<Pid, TaskRef>> = SpinLock::new(BTreeMap::new());

pub fn get_task(pid: Pid) -> Option<TaskRef> {
    TID_MAP.lock().get(&pid).cloned()
}

pub fn register_task(pid: Pid, task: TaskRef) {
    TID_MAP.lock().insert(pid, task);
}
