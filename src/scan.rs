//! CSV record scanner that classifies 64 bytes at a time with SIMD. Commas
//! and newlines end fields, and quotes are counted per field from a prefix
//! count, so the inner loop runs once per delimiter instead of once per byte.
//! Gives exactly the records of `crate::for_records`.

/// Comma, quote and newline bitmasks of the 64 bytes at `p`.
#[inline(always)]
fn masks(p: *const u8) -> (u64, u64, u64) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    unsafe {
        use std::arch::x86_64::*;
        let a = _mm256_loadu_si256(p as *const __m256i);
        let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
        let mm = |ch: u8| -> u64 {
            let k = _mm256_set1_epi8(ch as i8);
            let lo = _mm256_movemask_epi8(_mm256_cmpeq_epi8(a, k)) as u32 as u64;
            let hi = _mm256_movemask_epi8(_mm256_cmpeq_epi8(b, k)) as u32 as u64;
            lo | (hi << 32)
        };
        (mm(b','), mm(b'"'), mm(b'\n'))
    }
    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
    unsafe {
        use std::arch::x86_64::*;
        let v = [
            _mm_loadu_si128(p as *const __m128i),
            _mm_loadu_si128(p.add(16) as *const __m128i),
            _mm_loadu_si128(p.add(32) as *const __m128i),
            _mm_loadu_si128(p.add(48) as *const __m128i),
        ];
        let mm = |ch: u8| -> u64 {
            let k = _mm_set1_epi8(ch as i8);
            let mut m = 0u64;
            for (j, x) in v.iter().enumerate() {
                m |= (_mm_movemask_epi8(_mm_cmpeq_epi8(*x, k)) as u32 as u64) << (16 * j);
            }
            m
        };
        (mm(b','), mm(b'"'), mm(b'\n'))
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        use std::arch::aarch64::*;
        const W: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
        let w = vld1q_u8(W.as_ptr());
        let v0 = vld1q_u8(p);
        let v1 = vld1q_u8(p.add(16));
        let v2 = vld1q_u8(p.add(32));
        let v3 = vld1q_u8(p.add(48));
        let mm = |ch: u8| -> u64 {
            let k = vdupq_n_u8(ch);
            let t0 = vandq_u8(vceqq_u8(v0, k), w);
            let t1 = vandq_u8(vceqq_u8(v1, k), w);
            let t2 = vandq_u8(vceqq_u8(v2, k), w);
            let t3 = vandq_u8(vceqq_u8(v3, k), w);
            let s = vpaddq_u8(vpaddq_u8(t0, t1), vpaddq_u8(t2, t3));
            let s = vpaddq_u8(s, s);
            vgetq_lane_u64(vreinterpretq_u64_u8(s), 0)
        };
        (mm(b','), mm(b'"'), mm(b'\n'))
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let (mut c, mut q, mut n) = (0u64, 0u64, 0u64);
        for i in 0..64 {
            let b = unsafe { *p.add(i) };
            c |= ((b == b',') as u64) << i;
            q |= ((b == b'"') as u64) << i;
            n |= ((b == b'\n') as u64) << i;
        }
        (c, q, n)
    }
}

/// Calls f with the fields of every well-formed line of a chunk.
#[inline(always)]
pub fn for_records<'a, const N: usize>(buf: &'a [u8], mut f: impl FnMut([&'a [u8]; N])) {
    let len = buf.len();
    let base = buf.as_ptr();
    let mut out: [&'a [u8]; N] = [&[]; N];
    let mut k = 0usize; // fields closed in the current line
    let mut bad = false;
    let mut fs = 0usize; // current field start
    let mut ls = 0usize; // current line start
    let mut qb = 0u32; // quotes before this block
    let mut qs = 0u32; // quotes before fs
    let mut blk = 0usize;
    while blk < len {
        let (c, q, nl) = if blk + 64 <= len {
            masks(unsafe { base.add(blk) })
        } else {
            let mut tail = [0u8; 64];
            tail[..len - blk].copy_from_slice(&buf[blk..]);
            masks(tail.as_ptr())
        };
        let mut d = c | nl;
        while d != 0 {
            let i = d.trailing_zeros();
            d &= d - 1;
            let pos = blk + i as usize;
            let qn = qb + (q & ((1u64 << i) - 1)).count_ones();
            let nq = qn - qs;
            // fs <= pos < len, so both reads are inside buf; they only matter when nq == 2
            let first = unsafe { *base.add(fs) };
            let last = unsafe { *base.add(pos.saturating_sub(1)) };
            let wrapped = (nq == 2) & (first == b'"') & (last == b'"');
            let w = wrapped as usize;
            out[k.min(N - 1)] = unsafe { std::slice::from_raw_parts(base.add(fs + w), pos - fs - 2 * w) };
            bad |= !((nq == 0) | wrapped) | (k >= N);
            k += 1;
            fs = pos + 1;
            qs = qn;
            if (nl >> i) & 1 != 0 {
                if !bad & (k == N) {
                    f(out);
                }
                k = 0;
                bad = false;
                ls = fs;
            }
        }
        qb += q.count_ones();
        blk += 64;
    }
    if ls < len {
        // a last line with no newline
        let nq = qb - qs;
        let fld = &buf[fs..];
        let wrapped = nq == 2 && fld.len() >= 2 && fld[0] == b'"' && fld[fld.len() - 1] == b'"';
        if !bad && (nq == 0 || wrapped) && k + 1 == N {
            out[k] = if wrapped { &fld[1..fld.len() - 1] } else { fld };
            f(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(buf: &[u8]) {
        macro_rules! cmp {
            ($n:literal) => {{
                let mut want = vec![];
                crate::for_records::<$n>(buf, |x| want.push(x));
                let mut got = vec![];
                for_records::<$n>(buf, |x| got.push(x));
                assert_eq!(want, got, "N={} buf={:?}", $n, String::from_utf8_lossy(buf));
            }};
        }
        cmp!(2);
        cmp!(4);
        cmp!(7);
    }

    #[test]
    fn matches_scalar_scanner() {
        let mut files = 0;
        for d in ["../data/dev/events", "../data/dev/clicks", "../data/dev/links"] {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let b = std::fs::read(e.path()).unwrap();
                same(&b);
                // odd sub-slices: chunk edges in the middle of lines and blocks
                for (s, t) in [(1usize, 0usize), (63, 5), (64, 64), (65, 1), (100, 37)] {
                    if b.len() > s + t {
                        same(&b[s..b.len() - t]);
                    }
                }
                files += 1;
            }
        }
        assert!(files > 3);
        for d in ["../kit/starter-duckdb/starter-duckdb/fixtures"] {
            fn walk(p: &std::path::Path, n: &mut usize) {
                for e in std::fs::read_dir(p).unwrap().flatten() {
                    let q = e.path();
                    if q.is_dir() {
                        walk(&q, n);
                    } else if q.extension().map(|x| x == "csv").unwrap_or(false) {
                        same(&std::fs::read(&q).unwrap());
                        *n += 1;
                    }
                }
            }
            let mut n = 0;
            walk(std::path::Path::new(d), &mut n);
            assert!(n > 30, "{n} fixture files");
        }
        // random bytes over the characters that matter
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let alpha = b"ab,,\"\"\n\r";
        for round in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 300) as usize;
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(alpha[(x % alpha.len() as u64) as usize]);
            }
            if round % 3 == 0 && !v.is_empty() {
                let l = v.len();
                v[l - 1] = b'\n';
            }
            same(&v);
        }
    }
}
