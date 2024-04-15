#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cell::OnceCell;
use axfile::fops::File;
use axhal::paging::pgd_alloc;
use axhal::mem::phys_to_virt;
use axhal::paging::MappingFlags;
use axhal::paging::PageTable;
use axhal::paging::PagingResult;
use axio::SeekFrom;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use memory_addr::align_down_4k;
use spinlock::SpinNoIrq;
use mutex::Mutex;

pub type FileRef = Arc<Mutex<File>>;

static MM_UNIQUE_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone)]
pub struct VmAreaStruct {
    pub vm_start: usize,
    pub vm_end: usize,
    pub vm_pgoff: usize,
    pub vm_file: OnceCell<FileRef>,
    pub vm_flags: usize,
}

impl VmAreaStruct {
    pub fn new(
        vm_start: usize,
        vm_end: usize,
        vm_pgoff: usize,
        vm_file: Option<FileRef>,
        vm_flags: usize,
    ) -> Self {
        let vma = Self {
            vm_start,
            vm_end,
            vm_pgoff,
            vm_file: OnceCell::new(),
            vm_flags,
        };
        if let Some(f) = vm_file {
            let _ = vma.vm_file.set(f);
        }
        vma
    }
}

pub struct MmStruct {
    id: usize,
    pub vmas: BTreeMap<usize, VmAreaStruct>,
    pgd: Arc<SpinNoIrq<PageTable>>,
    brk: usize,
}

impl MmStruct {
    pub fn new() -> Self {
        Self {
            id: MM_UNIQUE_ID.fetch_add(1, Ordering::SeqCst),
            vmas: BTreeMap::new(),
            pgd: Arc::new(SpinNoIrq::new(pgd_alloc())),
            brk: 0,
        }
    }

    pub fn pgd(&self) -> Arc<SpinNoIrq<PageTable>> {
        self.pgd.clone()
    }

    pub fn root_paddr(&self) -> usize {
        self.pgd.lock().root_paddr().into()
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn brk(&self) -> usize {
        self.brk
    }

    pub fn set_brk(&mut self, brk: usize) {
        self.brk = brk;
    }

    pub fn map_region(&self, va: usize, pa: usize, len: usize, _uflags: usize) -> PagingResult {
        let flags =
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER;
        self.pgd
            .lock()
            .map_region(va.into(), pa.into(), len, flags, true)
    }

    pub fn fill_cache(&self, pa: usize, len: usize, file: &mut File, offset: usize) {
        let offset = align_down_4k(offset);
        let va = phys_to_virt(pa.into()).as_usize();

        let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };

        info!("offset {:#X} len {:#X}", offset, len);
        let _ = file.seek(SeekFrom::Start(offset as u64));

        let mut pos = 0;
        while pos < len {
            let ret = file.read(&mut buf[pos..]).unwrap();
            if ret == 0 {
                break;
            }
            pos += ret;
        }
        buf[pos..].fill(0);
    }
}
