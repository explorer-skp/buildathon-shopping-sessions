//! Global allocator: every block of 1 KB or more comes from a big region
//! that is backed by 2 MB transparent huge pages where the kernel allows it,
//! handed out by a per-thread bump pointer. The program builds its large
//! arrays once and exits without freeing them, so frees there are no-ops.
//! Huge pages cut the page faults of a 20M-event run several hundred fold.
//!
//! Region 1 is scratch: a thread allocates there only while it has selected
//! it, and `reset(1)` hands its memory out again once everything in it is
//! dead. Reused pages skip the kernel zeroing fresh pages get.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct Bump;

struct Region {
    base: AtomicUsize,
    end: AtomicUsize,
    next: AtomicUsize,
    epoch: AtomicUsize,
}

impl Region {
    const fn new() -> Self {
        Region { base: AtomicUsize::new(0), end: AtomicUsize::new(0), next: AtomicUsize::new(0), epoch: AtomicUsize::new(0) }
    }
}

static REGS: [Region; 2] = [Region::new(), Region::new()];
static ON: AtomicBool = AtomicBool::new(true);
const MIN: usize = 1024;
const BLOCK: usize = 4 << 20;
const HUGE: usize = 2 << 20;

thread_local! {
    // per region: (cursor, end, generation) of this thread's current block
    static TL: [Cell<(usize, usize, usize)>; 2] = const { [Cell::new((0, 0, 0)), Cell::new((0, 0, 0))] };
    static SEL: Cell<usize> = const { Cell::new(0) };
    static LOCAL_OFF: Cell<bool> = const { Cell::new(false) };
}

/// Sends this thread's allocations to the system allocator until `local_on`.
pub fn local_off() {
    LOCAL_OFF.with(|c| c.set(true));
}

pub fn local_on() {
    LOCAL_OFF.with(|c| c.set(false));
}

/// This thread's later allocations come from region `r` (0 or 1).
pub fn select(r: usize) {
    SEL.with(|c| c.set(if REGS[r].base.load(Ordering::Relaxed) != 0 { r } else { 0 }));
}

/// Hands region `r`'s memory out again. Everything allocated there must be
/// dead, and no thread may be allocating from it.
pub fn reset(r: usize) {
    let g = &REGS[r];
    g.next.store(g.base.load(Ordering::Relaxed), Ordering::Relaxed);
    g.epoch.fetch_add(1, Ordering::Release);
}

fn map(g: &Region, sizes: &[usize]) {
    #[cfg(unix)]
    unsafe {
        for &gb in sizes {
            let len = gb << 30;
            let p = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                continue;
            }
            let a = (p as usize + HUGE - 1) & !(HUGE - 1);
            #[cfg(target_os = "linux")]
            libc::madvise(a as *mut libc::c_void, p as usize + len - a, libc::MADV_HUGEPAGE);
            g.next.store(a, Ordering::Relaxed);
            g.end.store(p as usize + len, Ordering::Relaxed);
            g.base.store(a, Ordering::Release);
            return;
        }
    }
}

/// Maps the regions. Call once at the start of main, before other threads run.
pub fn init() {
    if std::env::var_os("SS_NOBUMP").is_some() {
        return;
    }
    map(&REGS[0], &[64, 32, 16, 8]);
    if REGS[0].base.load(Ordering::Relaxed) != 0 && std::env::var_os("SS_NOREUSE").is_none() {
        map(&REGS[1], &[32, 16, 8]);
    }
}

/// Sends later allocations to the system allocator, which reuses freed
/// memory. Blocks already handed out stay valid.
pub fn stop() {
    ON.store(false, Ordering::Relaxed);
}

#[inline(always)]
fn on() -> bool {
    REGS[0].base.load(Ordering::Relaxed) != 0 && ON.load(Ordering::Relaxed) && !LOCAL_OFF.with(|c| c.get())
}

#[inline(always)]
fn ours(p: *mut u8) -> bool {
    let p = p as usize;
    REGS.iter().any(|g| {
        let b = g.base.load(Ordering::Relaxed);
        b != 0 && p >= b && p < g.end.load(Ordering::Relaxed)
    })
}

#[inline(always)]
fn bump(r: usize, size: usize, align: usize) -> *mut u8 {
    let align = align.max(16);
    let g = &REGS[r];
    TL.with(|tl| {
        let c = &tl[r];
        let (cur, end, ep) = c.get();
        let now = g.epoch.load(Ordering::Relaxed);
        let s = (cur + align - 1) & !(align - 1);
        if cur != 0 && ep == now && s + size <= end {
            c.set((s + size, end, ep));
            return s as *mut u8;
        }
        if size + align > BLOCK / 4 {
            // a large block of its own; the thread keeps its current block
            let want = (size + align + 4095) & !4095;
            let b = g.next.fetch_add(want, Ordering::Relaxed);
            if b + want > g.end.load(Ordering::Relaxed) {
                return std::ptr::null_mut();
            }
            return ((b + align - 1) & !(align - 1)) as *mut u8;
        }
        let b = g.next.fetch_add(BLOCK, Ordering::Relaxed);
        if b + BLOCK > g.end.load(Ordering::Relaxed) {
            return std::ptr::null_mut();
        }
        let s = (b + align - 1) & !(align - 1);
        c.set((s + size, b + BLOCK, now));
        s as *mut u8
    })
}

unsafe impl GlobalAlloc for Bump {
    #[inline]
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() >= MIN && l.align() <= 4096 && on() {
            let p = bump(SEL.with(|c| c.get()), l.size(), l.align());
            if !p.is_null() {
                return p;
            }
        }
        unsafe { System.alloc(l) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if l.size() >= MIN && l.align() <= 4096 && on() {
            // region 0 is never reused, so its fresh memory is already zero
            let p = bump(0, l.size(), l.align());
            if !p.is_null() {
                return p;
            }
        }
        unsafe { System.alloc_zeroed(l) }
    }

    #[inline]
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if !ours(p) {
            unsafe { System.dealloc(p, l) }
        }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if ours(p) {
            if new <= l.size() {
                return p;
            }
            let q = unsafe { self.alloc(Layout::from_size_align_unchecked(new, l.align())) };
            if !q.is_null() {
                unsafe { std::ptr::copy_nonoverlapping(p, q, l.size()) };
            }
            return q;
        }
        if new >= MIN && l.align() <= 4096 && on() {
            let q = bump(SEL.with(|c| c.get()), new, l.align());
            if !q.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(p, q, l.size().min(new));
                    System.dealloc(p, l);
                }
                return q;
            }
        }
        unsafe { System.realloc(p, l, new) }
    }
}
