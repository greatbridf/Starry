use axconfig::{SMP, TASK_STACK_SIZE};
use axhal::mem::{virt_to_phys, PhysAddr, VirtAddr};

#[link_section = ".bss.stack"]
static mut SECONDARY_BOOT_STACK: [[u8; TASK_STACK_SIZE]; SMP - 1] = [[0; TASK_STACK_SIZE]; SMP - 1];

/// Starts the given secondary CPU with its boot stack.
pub fn start_given_secondary_cpu(hartid: usize, stack_top: PhysAddr) {
    extern "C" {
        fn _start_secondary();
    }
    if sbi_rt::probe_extension(sbi_rt::Hsm).is_unavailable() {
        log::warn!("HSM SBI extension is not supported for current SEE.");
        return;
    }
    let entry = virt_to_phys(VirtAddr::from(_start_secondary as usize));
    sbi_rt::hart_start(hartid, entry.as_usize(), stack_top.as_usize());
}

/// To start secondary CPUs after the primary CPU has been started.
pub fn start_secondary_cpus(primary_cpu_id: usize) {
    let mut logic_cpu_id = 0;
    for i in 0..SMP {
        if i != primary_cpu_id {
            let stack_top = virt_to_phys(VirtAddr::from(unsafe {
                SECONDARY_BOOT_STACK[logic_cpu_id].as_ptr_range().end as usize
            }));

            log::debug!("starting CPU {}...", i);
            start_given_secondary_cpu(i, stack_top);
            logic_cpu_id += 1;

            loop {
                if axruntime::mp::entered_cpus_num() > logic_cpu_id {
                    break;
                }
            }
        }
    }
}
