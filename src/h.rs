//! Hashes for short IDs (event, user, click and link IDs are about 9 bytes).
//! Up to 16 bytes, the first and last 8 bytes (or 4, or 1-3 picked bytes)
//! plus the length describe the string exactly, and one or two 128-bit
//! multiplies mix them, as in wyhash. Longer strings use xxh3.

const S0: u64 = 0xa076_1d64_78bd_642f;
const S1: u64 = 0xe703_7ed1_a0b4_28db;
const S2: u64 = 0x8ebc_6af0_9c88_c6e3;
const S3: u64 = 0x5899_65cc_7537_4cc3;

#[inline(always)]
fn mum(a: u64, b: u64) -> u64 {
    let r = (a as u128) * (b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

#[inline(always)]
fn r8(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

#[inline(always)]
fn r4(b: &[u8], i: usize) -> u64 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as u64
}

/// (first, last) words that, with the length, determine a string of at most 16 bytes.
#[inline(always)]
fn ends(b: &[u8]) -> (u64, u64) {
    let n = b.len();
    if n >= 8 {
        (r8(b, 0), r8(b, n - 8))
    } else if n >= 4 {
        (r4(b, 0), r4(b, n - 4))
    } else if n > 0 {
        (((b[0] as u64) << 16) | ((b[n >> 1] as u64) << 8) | b[n - 1] as u64, 0)
    } else {
        (0, 0)
    }
}

#[inline(always)]
pub fn h64(b: &[u8]) -> u64 {
    if b.len() > 16 {
        return xxhash_rust::xxh3::xxh3_64(b);
    }
    let (a, c) = ends(b);
    mum(mum(a ^ S0, c ^ S1 ^ b.len() as u64) ^ S2, S3 ^ b.len() as u64)
}

#[inline(always)]
pub fn h128(b: &[u8]) -> u128 {
    if b.len() > 16 {
        return xxhash_rust::xxh3::xxh3_128(b);
    }
    let (a, c) = ends(b);
    let n = b.len() as u64;
    let lo = mum(mum(a ^ S0, c ^ S1 ^ n) ^ S2, S3 ^ n);
    let hi = mum(mum(a ^ S3, c ^ S2 ^ n.rotate_left(32)) ^ S1, S0 ^ n);
    ((hi as u128) << 64) | lo as u128
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_short_ids() {
        // all 1-3 byte strings over a small alphabet, and random longer ones
        let alpha = b"0aZ,\"e9";
        let mut seen64 = std::collections::HashSet::new();
        let mut seen128 = std::collections::HashSet::new();
        let mut n = 0;
        for len in 0..=3usize {
            let mut idx = vec![0usize; len];
            loop {
                let s: Vec<u8> = idx.iter().map(|&i| alpha[i]).collect();
                assert!(seen64.insert(h64(&s)), "{s:?}");
                assert!(seen128.insert(h128(&s)));
                n += 1;
                let mut k = 0;
                while k < len {
                    idx[k] += 1;
                    if idx[k] < alpha.len() {
                        break;
                    }
                    idx[k] = 0;
                    k += 1;
                }
                if k == len {
                    break;
                }
            }
        }
        let mut x: u64 = 0x1234_5678_9abc_def1;
        for _ in 0..2_000_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = 4 + (x % 13) as usize;
            let s: Vec<u8> = (0..len).map(|i| b"abcdefghijklmnopqrstuvwxyz0123456789"[((x >> (i * 3 % 60)) % 36) as usize]).collect();
            if seen64.insert(h64(&s)) {
                assert!(seen128.insert(h128(&s)));
                n += 1;
            }
        }
        assert!(n > 1_000_000);
    }
}
