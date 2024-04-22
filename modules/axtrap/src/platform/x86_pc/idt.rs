use crate::arch::IdtStruct;
use lazy_init::LazyInit;

static IDT: LazyInit<IdtStruct> = LazyInit::new();

pub fn init_percpu_interrupt() {
    if !IDT.is_init() {
        // It will be finished by the primary core
        IDT.init_by(IdtStruct::new());
    }
    unsafe {
        IDT.load();
    }
}
