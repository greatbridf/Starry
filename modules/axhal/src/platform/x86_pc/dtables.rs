//! Description tables (per-CPU GDT, per-CPU ISS, IDT)

use crate::arch::{GdtStruct, TaskStateSegment};
use lazy_init::LazyInit;

#[percpu2::def_percpu]
static TSS: LazyInit<TaskStateSegment> = LazyInit::new();

#[percpu2::def_percpu]
static GDT: LazyInit<GdtStruct> = LazyInit::new();

fn init_percpu() {
    unsafe {
        let tss = TSS.current_ref_mut_raw();
        let gdt = GDT.current_ref_mut_raw();
        tss.init_by(TaskStateSegment::new());
        gdt.init_by(GdtStruct::new(tss));
        gdt.load();
        gdt.load_tss();
    }
}

/// Initializes IDT, GDT on the primary CPU.
pub fn init_primary() {
    axlog2::ax_println!("\nInitialize IDT & GDT...");
    init_percpu();
}

/// Initializes IDT, GDT on secondary CPUs.
#[cfg(feature = "smp")]
pub fn init_secondary() {
    init_percpu();
}

/// set tss stack top
pub fn set_tss_stack_top(kernel_stack_top: memory_addr::VirtAddr) {
    let tss = unsafe { TSS.current_ref_mut_raw() } as &mut TaskStateSegment;
    tss.privilege_stack_table[0] = x86_64::VirtAddr::new(kernel_stack_top.as_usize() as u64);
}
