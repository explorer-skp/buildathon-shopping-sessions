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

/// Bit i set when an odd number of bits of x are set at positions <= i.
#[inline(always)]
fn prefix_xor(mut x: u64) -> u64 {
    x ^= x << 1;
    x ^= x << 2;
    x ^= x << 4;
    x ^= x << 8;
    x ^= x << 16;
    x ^= x << 32;
    x
}

/// Masks of the 64 bytes at `blk`, reading a zero-padded copy for a short tail.
#[inline(always)]
fn block(buf: &[u8], blk: usize) -> (u64, u64, u64) {
    if blk + 64 <= buf.len() {
        masks(unsafe { buf.as_ptr().add(blk) })
    } else {
        let mut tail = [0u8; 64];
        tail[..buf.len() - blk].copy_from_slice(&buf[blk..]);
        masks(tail.as_ptr())
    }
}

const POS: u32 = 0x3FFF_FFFF;
const ANOM: u32 = 1 << 30;
const NL: u32 = 1 << 31;

thread_local! {
    static IDX: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Calls f with the fields of every well-formed line of a chunk.
///
/// Quotes are checked a block at a time: with the running quote parity, an
/// opening quote must follow a delimiter (or start the line), a closing quote
/// must precede one (or end the buffer), and no delimiter may sit inside
/// quotes. Exactly the lines breaking one of these have a field with quotes
/// other than one pair around all of it, so those lines are dropped and every
/// field of the others is stripped of its pair when it starts with a quote.
///
/// Each 64-byte block appends its delimiter positions to an index with a
/// fixed, unrolled write; each entry is flagged as a newline and as ending a
/// field that broke a quote rule. Lines are then taken N entries at a time.
#[inline(always)]
pub fn for_records<'a, const N: usize>(buf: &'a [u8], mut f: impl FnMut([&'a [u8]; N])) {
    let len = buf.len();
    if len == 0 {
        return;
    }
    assert!(len < (1 << 30), "chunk too large for the delimiter index");
    IDX.with(|cell| {
        let mut idx = cell.borrow_mut();
        idx.clear();
        let base = buf.as_ptr();
        let mut out: [&'a [u8]; N] = [&[]; N];
        let mut ls = 0usize; // start of the first line not yet taken
        let mut skipping = false; // that line has more than N fields; drop it at its newline
        let mut pdelim = 1u64; // the byte before this block ends a field (or there is none)
        let mut carry = 0u64; // quote parity carried in: 0 or all ones
        let mut pend = 0u32; // a quote rule broke after the last delimiter so far
        let mut cur = block(buf, 0);
        let mut blk = 0usize;
        // takes every complete line out of the index
        let mut take = |idx: &mut Vec<u32>, ls: &mut usize, skipping: &mut bool, f: &mut dyn FnMut([&'a [u8]; N])| {
            let w = idx.len();
            let mut j = 0usize;
            loop {
                if *skipping {
                    match idx[j..w].iter().position(|&e| e & NL != 0) {
                        Some(t) => {
                            *ls = (idx[j + t] & POS) as usize + 1;
                            j += t + 1;
                            *skipping = false;
                        }
                        None => {
                            j = w;
                            break;
                        }
                    }
                    continue;
                }
                if j + N > w {
                    // a short line can still end within the entries left
                    match idx[j..w].iter().position(|&e| e & NL != 0) {
                        Some(t) => {
                            *ls = (idx[j + t] & POS) as usize + 1;
                            j += t + 1;
                            continue;
                        }
                        None => break,
                    }
                }
                let mut nlb = 0u32;
                let mut an = 0u32;
                for k in 0..N {
                    let e = idx[j + k];
                    nlb |= (e >> 31) << k;
                    an |= e & ANOM;
                }
                if nlb == 1 << (N - 1) {
                    let mut fs = *ls;
                    for k in 0..N {
                        let pos = (idx[j + k] & POS) as usize;
                        // fs <= pos < len: a field that starts with a quote is wrapped in one pair
                        let wq = (unsafe { *base.add(fs) } == b'"') as usize;
                        out[k] = unsafe { std::slice::from_raw_parts(base.add(fs + wq), (pos - fs).saturating_sub(2 * wq)) };
                        fs = pos + 1;
                    }
                    if an == 0 {
                        f(out);
                    }
                    *ls = fs;
                    j += N;
                } else if nlb != 0 {
                    // too few fields
                    let t = nlb.trailing_zeros() as usize;
                    *ls = (idx[j + t] & POS) as usize + 1;
                    j += t + 1;
                } else {
                    // more than N fields
                    *skipping = true;
                    j += N;
                }
            }
            idx.drain(..j);
        };
        while blk < len {
            let (c, q, nl) = cur;
            let nblk = blk + 64;
            let next = if nblk < len { block(buf, nblk) } else { (0, 0, 0) };
            let d = c | nl;
            // a byte is followed by a delimiter, or by the end of the buffer
            let after = if nblk < len {
                ((next.0 | next.2) & 1) << 63
            } else if nblk == len {
                1u64 << 63
            } else {
                1u64 << (len - blk - 1)
            };
            let next_d = (d >> 1) | after;
            let prev_d = (d << 1) | pdelim;
            let mut px = prefix_xor(q) ^ carry;
            if nl & px != 0 {
                // a line ended inside quotes: restart the parity after its newline
                let mut m = nl;
                while m != 0 {
                    let j = m.trailing_zeros();
                    m &= m - 1;
                    if (px >> j) & 1 != 0 && j < 63 {
                        px ^= !0u64 << (j + 1);
                    }
                }
            }
            let mut amask = (d & px) | (q & px & !prev_d) | (q & !px & !next_d);
            carry = if (px >> 63) & 1 != 0 && (nl >> 63) & 1 == 0 { !0 } else { 0 };
            pdelim = d >> 63;
            let cnt = d.count_ones() as usize;
            let w = idx.len();
            idx.reserve(cnt + 8);
            let dst = unsafe { idx.as_mut_ptr().add(w) };
            let mut dd = d;
            // entries past cnt are scratch: they must not change amask
            let put = |k: usize, dd: &mut u64, amask: &mut u64| {
                let valid = (*dd != 0) as u64;
                let i = dd.trailing_zeros() & 63;
                *dd &= dd.wrapping_sub(1);
                let lm = (u64::MAX >> (63 - i)) & valid.wrapping_neg();
                let a = (*amask & lm != 0) as u32;
                *amask &= !lm;
                let e = (blk as u32 + i) | ((nl >> i) as u32 & 1) << 31 | a << 30;
                unsafe { dst.add(k).write(e) };
            };
            if cnt <= 8 {
                // fixed work per block
                for k in 0..8 {
                    put(k, &mut dd, &mut amask);
                }
            } else {
                for k in 0..cnt {
                    put(k, &mut dd, &mut amask);
                }
            }
            if cnt > 0 {
                // a rule broken after the previous delimiter belongs to this block's first field end
                unsafe { *dst |= pend << 30 };
                pend = (amask != 0) as u32;
            } else {
                pend |= (amask != 0) as u32;
            }
            unsafe { idx.set_len(w + cnt) };
            if idx.len() >= 4096 {
                take(&mut idx, &mut ls, &mut skipping, &mut f);
            }
            cur = next;
            blk = nblk;
        }
        take(&mut idx, &mut ls, &mut skipping, &mut f);
        if ls < len && !skipping {
            // a last line with no newline: its quotes must be closed at the end
            let k = idx.len();
            if k + 1 == N {
                let bad = carry != 0 || pend != 0 || idx.iter().any(|&e| e & ANOM != 0);
                if !bad {
                    let mut fs = ls;
                    for (kk, &e) in idx.iter().enumerate() {
                        let pos = (e & POS) as usize;
                        let wq = (buf[fs] == b'"') as usize;
                        out[kk] = &buf[fs + wq..pos - wq];
                        fs = pos + 1;
                    }
                    let fld = &buf[fs..];
                    let wq = (fld.first() == Some(&b'"')) as usize;
                    out[k] = &fld[wq..fld.len() - wq];
                    f(out);
                }
            }
        }
    });
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
        let dev = crate::test_dir("SS_TEST_DEV", "../data/dev");
        for d in ["events", "clicks", "links"] {
            for e in std::fs::read_dir(dev.join(d)).unwrap().flatten() {
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
        for d in [crate::test_dir("SS_TEST_FIXTURES", "../kit/starter-duckdb/starter-duckdb/fixtures")] {
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
            walk(&d, &mut n);
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
