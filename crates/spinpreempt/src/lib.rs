//! `no_std` spin lock implementation that can disable kernel local IRQs or
//! preemption while locking.
//!
//! # Cargo Features
//!
//! - `smp`: Use in the **multi-core** environment. For **single-core**
//!   environment (without this feature), the lock state is unnecessary and
//!   optimized out. CPU can always get the lock if we follow the proper guard
//!   in use. By default, this feature is disabled.

#![cfg_attr(not(test), no_std)]

mod base;

use preempt_guard::NoPreemptIrqSave;

pub use self::base::{BaseSpinLock, BaseSpinLockGuard};

/// A spin lock that disables kernel preemption and local IRQs while trying to
/// lock, and re-enables it after unlocking.
///
/// It can be used in the IRQ-enabled context.
pub type SpinLock<T> = BaseSpinLock<NoPreemptIrqSave, T>;

/// A guard that provides mutable data access for [`SpinNoIrq`].
pub type SpinLockGuard<'a, T> = BaseSpinLockGuard<'a, NoPreemptIrqSave, T>;
