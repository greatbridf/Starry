//! Trap handling.

use crate::arch::TrapFrame;

pub const TRAPFRAME_SIZE: usize = core::mem::size_of::<TrapFrame>();
pub const STACK_ALIGN: usize = 16;
