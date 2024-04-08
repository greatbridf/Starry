#![cfg_attr(not(test), no_std)]

extern crate alloc;
use alloc::string::String;

use memory_addr::{align_up_4k, is_aligned_4k};
use fileops::iovec;

#[macro_use]
extern crate log;

const MAX_SYSCALL_ARGS: usize = 6;
pub type SyscallArgs = [usize; MAX_SYSCALL_ARGS];

pub const AT_FDCWD: isize = -100;
pub const AT_EMPTY_PATH: isize = 0x1000;

pub fn do_syscall(args: SyscallArgs, sysno: usize) -> usize {
    match sysno {
        LINUX_SYSCALL_FACCESSAT => {
            linux_syscall_faccessat(args)
        },
        LINUX_SYSCALL_OPENAT => {
            linux_syscall_openat(args)
        },
        LINUX_SYSCALL_CLOSE => {
            linux_syscall_close(args)
        },
        LINUX_SYSCALL_READ => {
            linux_syscall_read(args)
        },
        LINUX_SYSCALL_WRITE => {
            linux_syscall_write(args)
        },
        LINUX_SYSCALL_WRITEV => {
            linux_syscall_writev(args)
        },
        LINUX_SYSCALL_READLINKAT => {
            usize::MAX
        },
        LINUX_SYSCALL_FSTATAT => {
            linux_syscall_fstatat(args)
        },
        LINUX_SYSCALL_UNAME => {
            linux_syscall_uname(args)
        },
        LINUX_SYSCALL_BRK => {
            linux_syscall_brk(args)
        },
        LINUX_SYSCALL_MUNMAP => {
            linux_syscall_munmap(args)
        },
        LINUX_SYSCALL_MMAP => {
            linux_syscall_mmap(args)
        },
        LINUX_SYSCALL_MPROTECT => {
            linux_syscall_mprotect(args)
        },
        LINUX_SYSCALL_SET_TID_ADDRESS => {
            linux_syscall_set_tid_address(args)
        },
        LINUX_SYSCALL_SET_ROBUST_LIST=> {
            linux_syscall_set_robust_list(args)
        },
        LINUX_SYSCALL_PRLIMIT64 => {
            linux_syscall_prlimit64(args)
        },
        LINUX_SYSCALL_GETRANDOM => {
            linux_syscall_getrandom(args)
        },
        LINUX_SYSCALL_CLOCK_GETTIME => {
            linux_syscall_clock_gettime(args)
        },
        LINUX_SYSCALL_RT_SIGPROCMASK => {
            linux_syscall_rt_sigprocmask(args)
        },
        LINUX_SYSCALL_RT_SIGACTION => {
            linux_syscall_rt_sigaction(args)
        },
        LINUX_SYSCALL_GETTID => {
            linux_syscall_gettid(args)
        },
        LINUX_SYSCALL_GETPID => {
            linux_syscall_getpid(args)
        },
        LINUX_SYSCALL_TGKILL => {
            linux_syscall_tgkill(args)
        },
        LINUX_SYSCALL_EXIT => {
            linux_syscall_exit(args)
        },
        LINUX_SYSCALL_EXIT_GROUP => {
            linux_syscall_exit_group(args)
        },
        _ => {
            panic!("Unsupport sysno: {}", sysno);
            0
        }
    }
}

//
// Linux syscall
//
const LINUX_SYSCALL_FACCESSAT:  usize = 0x30;
const LINUX_SYSCALL_OPENAT:     usize = 0x38;
const LINUX_SYSCALL_CLOSE:      usize = 0x39;
const LINUX_SYSCALL_READ:       usize = 0x3f;
const LINUX_SYSCALL_WRITE:      usize = 0x40;
const LINUX_SYSCALL_WRITEV:     usize = 0x42;
const LINUX_SYSCALL_READLINKAT: usize = 0x4e;
const LINUX_SYSCALL_FSTATAT:    usize = 0x4f;
const LINUX_SYSCALL_EXIT:       usize = 0x5d;
const LINUX_SYSCALL_EXIT_GROUP: usize = 0x5e;
const LINUX_SYSCALL_TGKILL:     usize = 0x83;
const LINUX_SYSCALL_UNAME:      usize = 0xa0;
const LINUX_SYSCALL_GETPID:     usize = 0xac;
const LINUX_SYSCALL_GETTID:     usize = 0xb2;
const LINUX_SYSCALL_BRK:        usize = 0xd6;
const LINUX_SYSCALL_MUNMAP:     usize = 0xd7;
const LINUX_SYSCALL_MMAP:       usize = 0xde;
const LINUX_SYSCALL_MPROTECT:   usize = 0xe2;
const LINUX_SYSCALL_PRLIMIT64:  usize = 0x105;
const LINUX_SYSCALL_GETRANDOM:  usize = 0x116;

const LINUX_SYSCALL_SET_TID_ADDRESS:    usize = 0x60;
const LINUX_SYSCALL_SET_ROBUST_LIST:    usize = 0x63;
const LINUX_SYSCALL_CLOCK_GETTIME:      usize = 0x71;
const LINUX_SYSCALL_RT_SIGACTION:       usize = 0x86;
const LINUX_SYSCALL_RT_SIGPROCMASK:     usize = 0x87;


/// # Safety
///
/// The caller must ensure that the pointer is valid and
/// points to a valid C string.
/// The string must be null-terminated.
pub unsafe fn get_str_len(ptr: *const u8) -> usize {
    let mut cur = ptr as usize;
    while *(cur as *const u8) != 0 {
        cur += 1;
    }
    cur - ptr as usize
}

/// # Safety
///
/// The caller must ensure that the pointer is valid and
/// points to a valid C string.
pub fn raw_ptr_to_ref_str(ptr: *const u8) -> &'static str {
    let len = unsafe { get_str_len(ptr) };
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(slice) {
        s
    } else {
        panic!("not utf8 slice");
    }
}

pub fn get_user_str(ptr: usize) -> String {
    let ptr = ptr as *const u8;
    axhal::arch::enable_sum();
    let ptr = raw_ptr_to_ref_str(ptr);
    let s = String::from(ptr);
    axhal::arch::disable_sum();
    s
}

fn linux_syscall_faccessat(args: SyscallArgs) -> usize {
    warn!("linux_syscall_faccessat");
    0
}

fn linux_syscall_openat(args: SyscallArgs) -> usize {
    let [dtd, filename, flags, mode, ..] = args;

    let filename = get_user_str(filename);
    info!("filename: {}\n", filename);
    fileops::openat(dtd, &filename, flags, mode)
}

fn linux_syscall_close(_args: SyscallArgs) -> usize {
    info!("Todo: linux_syscall_close");
    0
}

fn linux_syscall_read(args: SyscallArgs) -> usize {
    let [fd, buf, count, ..] = args;

    let user_buf = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, count)
    };

    fileops::read(fd, user_buf)
}

fn linux_syscall_write(args: SyscallArgs) -> usize {
    let [fd, buf, size, ..] = args;
    info!("write: {:#x}, {:#x}, {:#x}", fd, buf, size);

    let buf = unsafe { core::slice::from_raw_parts(buf as *const u8, size) };

    fileops::write(buf)
}

fn linux_syscall_writev(args: SyscallArgs) -> usize {
    let [fd, array, size, ..] = args;
    info!("writev: {:#x}, {:#x}, {:#x}", fd, array, size);

    let iov_array = unsafe { core::slice::from_raw_parts(array as *const iovec, size) };
    fileops::writev(iov_array)
}

fn linux_syscall_fstatat(args: SyscallArgs) -> usize {
    let [dirfd, pathname, statbuf, flags, ..] = args;

    info!("###### fstatat!!! {:#x} {:#x} {:#x}", dirfd, statbuf, flags);
    if (flags as isize & AT_EMPTY_PATH) == 0 {
        // Todo: Handle this situation.
        let pathname = get_user_str(pathname);
        warn!("!!! implement NON-EMPTY for pathname: {}\n", pathname);
        return 0;
    }

    // Todo: use real pathname to replace ""
    fileops::fstatat(dirfd, "", statbuf, flags)
}

fn linux_syscall_mmap(args: SyscallArgs) -> usize {
    let [va, len, prot, flags, fd, offset] = args;
    assert!(is_aligned_4k(va));
    debug!("###### mmap!!! {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}", va, len, prot, flags, fd, offset);

    mmap::mmap(va, len, prot, flags, fd, offset).unwrap()
}

fn linux_syscall_mprotect(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_mprotect");
    0
}

fn linux_syscall_set_tid_address(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_set_tid_address");
    0
}

fn linux_syscall_set_robust_list(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_set_robust_list");
    0
}

fn linux_syscall_prlimit64(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_prlimit64");
    0
}

fn linux_syscall_getrandom(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_getrandom");
    0
}

fn linux_syscall_clock_gettime(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_clock_gettime");
    0
}

fn linux_syscall_rt_sigprocmask(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_rt_sigprocmask");
    0
}

fn linux_syscall_rt_sigaction(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_rt_sigaction");
    0
}

fn linux_syscall_gettid(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_gettid");
    0
}

fn linux_syscall_getpid(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_getpid");
    0
}

fn linux_syscall_tgkill(args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_tgkill");
    0
}

const UTS_LEN: usize = 64;

#[repr(C)]
struct utsname {
    sysname: [u8; UTS_LEN + 1],
    nodename: [u8; UTS_LEN + 1],
    release: [u8; UTS_LEN + 1],
    version: [u8; UTS_LEN + 1],
    machine: [u8; UTS_LEN + 1],
    domainname: [u8; UTS_LEN + 1],
}

fn linux_syscall_uname(args: SyscallArgs) -> usize {
    let ptr = args[0];
    info!("uname: {:#x}", ptr);

    let uname = unsafe { (ptr as *mut utsname).as_mut().unwrap() };

    init_bytes_from_str(&mut uname.sysname[..], "Linux");
    init_bytes_from_str(&mut uname.nodename[..], "host");
    init_bytes_from_str(&mut uname.domainname[..], "(none)");
    init_bytes_from_str(&mut uname.release[..], "5.9.0-rc4+");
    init_bytes_from_str(&mut uname.version[..], "#1337 SMP Fri Mar 4 09:36:42 CST 2022");
    init_bytes_from_str(&mut uname.machine[..], "riscv64");

    return 0;
}

fn init_bytes_from_str(dst: &mut [u8], src: &str) {
    let src = src.as_bytes();
    let (left, right) = dst.split_at_mut(src.len());
    axhal::arch::enable_sum();
    left.copy_from_slice(src);
    right.fill(0);
    axhal::arch::disable_sum();
}

fn linux_syscall_brk(args: SyscallArgs) -> usize {
    let va = align_up_4k(args[0]);
    mmap::set_brk(va)
}

fn linux_syscall_munmap(args: SyscallArgs) -> usize {
    let [va, len, ..] = args;
    debug!("munmap!!! {:#x} {:#x}", va, len);
    unimplemented!();
    //return 0;
}

fn linux_syscall_exit(args: SyscallArgs) -> usize {
    let ret = args[0] as i32;
    warn!("impl exit ...{}", ret);
    task::exit(ret);
}

fn linux_syscall_exit_group(_tf: SyscallArgs) -> usize {
    warn!("impl exit_group!");
    return 0;
}

pub fn init() {
}
