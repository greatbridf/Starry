mod boot;

#[cfg(feature = "smp")]
pub mod mp;

unsafe extern "C" fn rust_entry(cpu_id: usize, dtb: usize) {
    axhal::mem::clear_bss();
    axhal::cpu::init_primary(cpu_id);

    axtrap::init_trap();
    axlog::init();
    axlog::set_max_level(option_env!("AX_LOG").unwrap_or("")); // no effect if set `log-level-*` features

    #[cfg(feature = "alloc")]
    crate::alloc::init_allocator();

    #[cfg(feature = "smp")]
    mp::start_secondary_cpus(cpu_id);

    axruntime::rust_main(cpu_id, dtb);
}

#[cfg(feature = "smp")]
unsafe extern "C" fn rust_entry_secondary(cpu_id: usize) {
    axtrap::init_trap();
    axhal::cpu::init_secondary(cpu_id);
    axruntime::mp::rust_main_secondary(cpu_id);
}
