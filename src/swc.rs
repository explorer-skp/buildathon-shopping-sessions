//! Software write-combining for rows scattered over many vectors: each vector
//! gets a stage of eight rows, and a full stage (three cache lines for 24-byte
//! rows) is written out with non-temporal stores where the destination is
//! aligned, so the destination lines are never read from memory first.

pub struct Swc<T: Copy> {
    stage: Vec<T>,
    cnt: Vec<u8>,
}

impl<T: Copy> Swc<T> {
    pub fn new(n: usize) -> Self {
        let mut stage = Vec::with_capacity(n * 8);
        unsafe { stage.set_len(n * 8) };
        Swc { stage, cnt: vec![0; n] }
    }

    /// Rows staged for vector b and not yet written.
    #[inline(always)]
    pub fn pending(&self, b: usize) -> usize {
        self.cnt[b] as usize
    }

    #[inline(always)]
    pub fn push(&mut self, dst: &mut [Vec<T>], b: usize, x: T) {
        let c = self.cnt[b] as usize;
        unsafe { *self.stage.as_mut_ptr().add(b * 8 + c) = x };
        if c == 7 {
            self.cnt[b] = 0;
            flush8(&mut dst[b], unsafe { self.stage.as_ptr().add(b * 8) });
        } else {
            self.cnt[b] = (c + 1) as u8;
        }
    }

    /// Writes the partial stages and makes the streamed stores visible.
    pub fn finish(&mut self, dst: &mut [Vec<T>]) {
        for b in 0..self.cnt.len() {
            let c = self.cnt[b] as usize;
            if c > 0 {
                dst[b].extend_from_slice(&self.stage[b * 8..b * 8 + c]);
                self.cnt[b] = 0;
            }
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            std::arch::x86_64::_mm_sfence()
        };
    }
}

#[inline(always)]
fn flush8<T: Copy>(v: &mut Vec<T>, src: *const T) {
    v.reserve(8);
    let len = v.len();
    let p = unsafe { v.as_mut_ptr().add(len) };
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        if std::mem::size_of::<T>() == 24 && (p as usize) % 32 == 0 {
            use std::arch::x86_64::*;
            unsafe {
                let s = src as *const u8;
                let d = p as *mut u8;
                for k in 0..6 {
                    let x = _mm256_loadu_si256(s.add(32 * k) as *const __m256i);
                    _mm256_stream_si256(d.add(32 * k) as *mut __m256i, x);
                }
                v.set_len(len + 8);
            }
            return;
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src, p, 8);
        v.set_len(len + 8);
    }
}
