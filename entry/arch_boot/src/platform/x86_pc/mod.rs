mod boot;

#[cfg(feature = "smp")]
pub mod mp;

fn current_cpu_id() -> usize {
    match raw_cpuid::CpuId::new().get_feature_info() {
        Some(finfo) => finfo.initial_local_apic_id() as usize,
        None => 0,
    }
}

unsafe extern "C" fn rust_entry(magic: usize, _mbi: usize) {
    // TODO: handle multiboot info
    if magic == self::boot::MULTIBOOT_BOOTLOADER_MAGIC {
        axhal::mem::clear_bss();
        axhal::cpu::init_primary(current_cpu_id());
        axtrap::init_interrupt();
        axlog::init();
        axlog::set_max_level(option_env!("AX_LOG").unwrap_or("")); // no effect if set `log-level-*` features

        #[cfg(feature = "alloc")]
        crate::alloc::init_allocator();

        axhal::console::init();
        axhal::x86_64::dtables::init_primary();
        axhal::x86_64::time::init_early();
        axlog::ax_println!("test");
        let cpu_id = current_cpu_id();
        #[cfg(feature = "smp")]
        crate::mp::start_secondary_cpus(cpu_id);

        axruntime::rust_main(cpu_id, 0);
    }
}

#[allow(unused_variables)]
unsafe extern "C" fn rust_entry_secondary(magic: usize) {
    #[cfg(feature = "smp")]
    if magic == self::boot::MULTIBOOT_BOOTLOADER_MAGIC {
        axtrap::init_interrupt();
        axhal::cpu::init_secondary(current_cpu_id());
        axhal::x86_64::dtables::init_secondary();
        axruntime::mp::rust_main_secondary(current_cpu_id());
    }
}
