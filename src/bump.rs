//! Global allocator: every block of 1 KB or more comes from one big region
//! that is backed by 2 MB transparent huge pages where the kernel allows it,
//! handed out by a per-thread bump pointer. The program builds its large
//! arrays once and exits without freeing them, so frees there are no-ops.
//! Huge pages cut the page faults of a 20M-event run several hundred fold.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct Bump;

static BASE: AtomicUsize = AtomicUsize::new(0);
static END: AtomicUsize = AtomicUsize::new(0);
static NEXT: AtomicUsize = AtomicUsize::new(0);
static ON: AtomicBool = AtomicBool::new(true);
const MIN: usize = 1024;
const BLOCK: usize = 4 << 20;
const HUGE: usize = 2 << 20;

thread_local! {
    static TL: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

/// Maps the region. Call once at the start of main, before other threads run.
pub fn init() {
    if std::env::var_os("SS_NOBUMP").is_some() {
        return;
    }
    #[cfg(unix)]
    unsafe {
        for gb in [64usize, 32, 16, 8] {
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
            NEXT.store(a, Ordering::Relaxed);
            END.store(p as usize + len, Ordering::Relaxed);
            BASE.store(a, Ordering::Release);
            return;
        }
    }
}

/// Sends later allocations to the system allocator, which reuses freed
/// memory. Blocks already handed out stay valid.
pub fn stop() {
    ON.store(false, Ordering::Relaxed);
}

#[inline(always)]
fn on() -> bool {
    BASE.load(Ordering::Relaxed) != 0 && ON.load(Ordering::Relaxed)
}

#[inline(always)]
fn ours(p: *mut u8) -> bool {
    let b = BASE.load(Ordering::Relaxed);
    b != 0 && (p as usize) >= b && (p as usize) < END.load(Ordering::Relaxed)
}

#[inline(always)]
fn bump(size: usize, align: usize) -> *mut u8 {
    let align = align.max(16);
    TL.with(|c| {
        let (cur, end) = c.get();
        let s = (cur + align - 1) & !(align - 1);
        if cur != 0 && s + size <= end {
            c.set((s + size, end));
            return s as *mut u8;
        }
        if size + align > BLOCK / 4 {
            // a large block of its own; the thread keeps its current block
            let want = (size + align + 4095) & !4095;
            let b = NEXT.fetch_add(want, Ordering::Relaxed);
            if b + want > END.load(Ordering::Relaxed) {
                return std::ptr::null_mut();
            }
            return ((b + align - 1) & !(align - 1)) as *mut u8;
        }
        let b = NEXT.fetch_add(BLOCK, Ordering::Relaxed);
        if b + BLOCK > END.load(Ordering::Relaxed) {
            return std::ptr::null_mut();
        }
        let s = (b + align - 1) & !(align - 1);
        c.set((s + size, b + BLOCK));
        s as *mut u8
    })
}

unsafe impl GlobalAlloc for Bump {
    #[inline]
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() >= MIN && l.align() <= 4096 && on() {
            let p = bump(l.size(), l.align());
            if !p.is_null() {
                return p;
            }
        }
        unsafe { System.alloc(l) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if l.size() >= MIN && l.align() <= 4096 && on() {
            // fresh region memory is already zero
            let p = bump(l.size(), l.align());
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
            let q = bump(new, l.align());
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
