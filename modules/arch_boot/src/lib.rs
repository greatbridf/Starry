#![cfg_attr(not(test), no_std)]
#![feature(naked_functions)]
#![feature(asm_const)]
#[cfg(feature = "alloc")]
mod alloc;

mod platform;
