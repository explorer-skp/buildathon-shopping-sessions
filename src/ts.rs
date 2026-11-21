//! Timestamp parsing with 8-byte loads and a month table. Same results as
//! `crate::parse_ts`, which still handles every uncommon shape.

const Y0: i64 = 1900;
const NY: usize = 300;

const fn dfc(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Day number of the first day of each month of years Y0..Y0+NY, plus one.
static MONTH0: [i32; NY * 12 + 1] = {
    let mut t = [0i32; NY * 12 + 1];
    let mut i = 0;
    while i <= NY * 12 {
        t[i] = dfc(Y0 + (i / 12) as i64, (i % 12) as i64 + 1, 1) as i32;
        i += 1;
    }
    t
};

#[inline(always)]
fn ld8(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

/// True when all 8 bytes are ASCII digits.
#[inline(always)]
fn all_digits(v: u64) -> bool {
    ((v & 0xF0F0_F0F0_F0F0_F0F0) | ((v.wrapping_add(0x0606_0606_0606_0606) & 0xF0F0_F0F0_F0F0_F0F0) >> 4))
        == 0x3333_3333_3333_3333
}

/// Value of 8 ASCII digits, the first one in the low byte.
#[inline(always)]
fn eight(v: u64) -> u64 {
    let v = (v & 0x0F0F_0F0F_0F0F_0F0F).wrapping_mul(2561) >> 8;
    let v = (v & 0x00FF_00FF_00FF_00FF).wrapping_mul(6553601) >> 16;
    (v & 0x0000_FFFF_0000_FFFF).wrapping_mul(42949672960001) >> 32
}

#[inline(always)]
pub fn parse_ts(b: &[u8]) -> Option<i64> {
    let n = b.len();
    if n == 13 {
        let a = ld8(b, 0);
        let c = ld8(b, 5);
        if all_digits(a) & all_digits(c) {
            // the last five digits are the top five bytes of c
            let lo = eight((c & !0xFF_FFFF) | 0x30_3030);
            return Some((eight(a) * 100_000 + lo) as i64);
        }
        return crate::parse_ts(b);
    }
    if n != 20 && n != 25 {
        return crate::parse_ts(b);
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
    let (y, mo, d, h, mi, s) = {
        // one 16-byte load checks "YYYY-MM-DDTHH:MM" and turns its digit pairs into numbers
        use std::arch::x86_64::*;
        let (seq, dig, p) = unsafe {
            let v = _mm_loadu_si128(b.as_ptr() as *const __m128i);
            let sep = _mm_setr_epi8(0, 0, 0, 0, b'-' as i8, 0, 0, b'-' as i8, 0, 0, b'T' as i8, 0, 0, b':' as i8, 0, 0);
            let seq = _mm_movemask_epi8(_mm_cmpeq_epi8(v, sep)) as u32;
            let dv = _mm_sub_epi8(v, _mm_set1_epi8(b'0' as i8));
            let nine = _mm_set1_epi8(9);
            let dig = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_max_epu8(dv, nine), nine)) as u32;
            let g = _mm_shuffle_epi8(dv, _mm_setr_epi8(0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, -1, -1, -1, -1));
            let p = _mm_maddubs_epi16(g, _mm_setr_epi8(10, 1, 10, 1, 10, 1, 10, 1, 10, 1, 10, 1, 0, 0, 0, 0));
            (seq, dig, p)
        };
        // separators at 4, 7, 10, 13 (and 16 below); otherwise only F3 can apply
        if seq & 0x2490 != 0x2490 {
            return crate::parse_ts(b);
        }
        // with any of those separators present, F3 fails too, so the answer is None
        if b[16] != b':' || dig & 0xDB6F != 0xDB6F {
            return None;
        }
        let s = crate::d2(b, 17)?;
        let lane = |i: i32| -> i64 {
            (unsafe {
                match i {
                    0 => _mm_extract_epi16(p, 0),
                    1 => _mm_extract_epi16(p, 1),
                    2 => _mm_extract_epi16(p, 2),
                    3 => _mm_extract_epi16(p, 3),
                    4 => _mm_extract_epi16(p, 4),
                    _ => _mm_extract_epi16(p, 5),
                }
            }) as i64
        };
        (lane(0) * 100 + lane(1), lane(2), lane(3), lane(4), lane(5), s)
    };
    #[cfg(not(all(target_arch = "x86_64", target_feature = "ssse3")))]
    let (y, mo, d, h, mi, s) = {
        let w0 = ld8(b, 0); // YYYY-MM-
        let w1 = ld8(b, 8); // DDTHH:MM
        let w2 = ld8(b, 12); // H:MM:SS?
        if (w0 & 0xFF00_00FF_0000_0000) != 0x2D00_002D_0000_0000
            || (w1 & 0x0000_FF00_00FF_0000) != 0x0000_3A00_0054_0000
            || (w2 >> 32) & 0xFF != 0x3A
        {
            return crate::parse_ts(b);
        }
        let v0 = (w0 & !0xFF00_00FF_0000_0000) | 0x3000_0030_0000_0000;
        let v1 = (w1 & !0x0000_FF00_00FF_0000) | 0x0000_3000_0030_0000;
        let v2 = (w2 & 0x00FF_FF00_0000_0000) | 0x3000_0030_3030_3030;
        if !(all_digits(v0) & all_digits(v1) & all_digits(v2)) {
            return None;
        }
        let x0 = v0 - 0x3030_3030_3030_3030;
        let x1 = v1 - 0x3030_3030_3030_3030;
        let x2 = v2 - 0x3030_3030_3030_3030;
        let t0 = x0 * 10 + (x0 >> 8);
        let t1 = x1 * 10 + (x1 >> 8);
        let y = ((t0 & 0xFF) * 100 + ((t0 >> 16) & 0xFF)) as i64;
        let mo = ((t0 >> 40) & 0xFF) as i64;
        let d = (t1 & 0xFF) as i64;
        let h = ((t1 >> 24) & 0xFF) as i64;
        let mi = ((t1 >> 48) & 0xFF) as i64;
        let s = (((x2 >> 40) & 0xFF) * 10 + ((x2 >> 48) & 0xFF)) as i64;
        (y, mo, d, h, mi, s)
    };
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || s > 59 || d < 1 {
        return None;
    }
    let days = if (Y0..Y0 + NY as i64).contains(&y) {
        let i = ((y - Y0) * 12 + mo - 1) as usize;
        let first = MONTH0[i] as i64;
        if d > MONTH0[i + 1] as i64 - first {
            return None;
        }
        first + d - 1
    } else {
        return crate::parse_ts(b);
    };
    let mut ms = (days * 86400 + h * 3600 + mi * 60 + s) * 1000;
    let tail = b[19];
    if n == 20 {
        if tail != b'Z' {
            return None;
        }
    } else {
        let sign = match tail {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        if b[22] != b':' {
            return None;
        }
        let oh = crate::d2(b, 20)?;
        let om = crate::d2(b, 23)?;
        if oh > 23 || om > 59 {
            return None;
        }
        ms -= sign * (oh * 3600 + om * 60) * 1000;
    }
    Some(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(b: &[u8]) {
        assert_eq!(parse_ts(b), crate::parse_ts(b), "{:?}", String::from_utf8_lossy(b));
    }

    #[test]
    fn matches_reference_parser() {
        let mut n = 0usize;
        let dev = crate::test_dir("SS_TEST_DEV", "../data/dev");
        for d in ["events", "clicks"] {
            for e in std::fs::read_dir(dev.join(d)).unwrap().flatten() {
                let b = std::fs::read(e.path()).unwrap();
                crate::scan::for_records::<7>(&b, |f| {
                    same(f[2]);
                    same(f[3]);
                    n += 2;
                });
                crate::scan::for_records::<4>(&b, |f| {
                    same(f[3]);
                    n += 1;
                });
            }
        }
        assert!(n > 1_000_000, "{n}");
        let base: [&[u8]; 8] = [
            b"2027-12-18T22:22:54Z",
            b"2027-12-12T12:21:38-06:00",
            b"2027-12-18T01:06:04+05:00",
            b"1829168499000",
            b"2024-02-29T23:59:59Z",
            b"2023-02-29T00:00:00Z",
            b"1899-12-31T23:59:59Z",
            b"2199-12-31T23:59:59+23:59",
        ];
        let alpha = b"0123456789-T:Z+ x9";
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2_000_000 {
            let mut v = base[(rnd() % base.len() as u64) as usize].to_vec();
            for _ in 0..(rnd() % 3) {
                let i = (rnd() % v.len() as u64) as usize;
                v[i] = alpha[(rnd() % alpha.len() as u64) as usize];
            }
            same(&v);
            // random digit strings and lengths
            let len = (rnd() % 27) as usize;
            let w: Vec<u8> = (0..len).map(|_| b'0' + (rnd() % 10) as u8).collect();
            same(&w);
        }
        for y in 0..10000 {
            for m in [1, 2, 3, 12] {
                for d in [1, 28, 29, 30, 31] {
                    same(format!("{y:04}-{m:02}-{d:02}T00:00:00Z").as_bytes());
                }
            }
        }
    }
}
