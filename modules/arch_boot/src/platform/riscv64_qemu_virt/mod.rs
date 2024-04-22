mod boot;

#[cfg(feature = "irq")]
pub mod irq;

#[cfg(feature = "smp")]
pub mod mp;

unsafe extern "C" fn rust_entry(cpu_id: usize, dtb: usize) {
    axhal::mem::clear_bss();
    axhal::cpu::init_primary(cpu_id);
    axtrap::init_trap();
    #[cfg(feature = "alloc")]
    crate::alloc::init_allocator();

    // #[cfg(feature = "monolithic")]
    riscv::register::sstatus::set_sum();

    #[cfg(feature = "smp")]
    mp::start_secondary_cpus(cpu_id);

    mkboot::rust_main(cpu_id, dtb);
}

#[cfg(feature = "smp")]
unsafe extern "C" fn rust_entry_secondary(cpu_id: usize) {
    axtrap::init_trap_vector();
    axhal::cpu::init_secondary(cpu_id);
    mkboot::mp::rust_main_secondary(cpu_id);
}
