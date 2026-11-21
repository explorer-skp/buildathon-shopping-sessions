//! Shopping Sessions pipeline: one pass over memory-mapped CSV files, all
//! rules from rules.md implemented by hand so the CSV dialect is exact.

use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use h::{h128 as xxh3_128, h64 as xxh3_64};

mod bump;
mod h;
mod pq;
mod scan;
mod swc;
mod ts;

#[global_allocator]
static GA: bump::Bump = bump::Bump;

/// Keys are already xxh3 hashes: pass them straight through.
#[derive(Default, Clone, Copy)]
struct IdH(u64);
impl std::hash::Hasher for IdH {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }
    fn write_u64(&mut self, x: u64) {
        self.0 = x;
    }
}
type IdB = std::hash::BuildHasherDefault<IdH>;
type IdMap<V> = HashMap<u64, V, IdB>;

const MIN30: i64 = 1_800_000;
const DAY: i64 = 86_400_000;
const WEEK: i64 = 7 * DAY;

macro_rules! log {
    ($($t:tt)*) => { if std::env::var_os("SS_QUIET").is_none() || std::env::var_os("SS_LOG").is_some() { eprintln!($($t)*); } }
}

// ------------------------------------------------------------------ CSV

/// Strips the quotes of one field given how many quote bytes it holds.
#[inline(always)]
fn unquote(f: &[u8], quotes: u32) -> Option<&[u8]> {
    if quotes == 0 {
        Some(f)
    } else if quotes == 2 && f.len() >= 2 && f[0] == b'"' && f[f.len() - 1] == b'"' {
        Some(&f[1..f.len() - 1])
    } else {
        None
    }
}

/// Same contract as `fields`, in one pass over the line's bytes: commas end
/// fields, and a field may hold quotes only as one pair around all of it.
#[inline(always)]
fn fields_fast<const N: usize>(line: &[u8]) -> Option<[&[u8]; N]> {
    let mut out: [&[u8]; N] = [&[]; N];
    let mut k = 0usize;
    let mut start = 0usize;
    let mut quotes = 0u32;
    for (i, &c) in line.iter().enumerate() {
        if c == b',' {
            if k + 1 >= N {
                return None;
            }
            out[k] = unquote(&line[start..i], quotes)?;
            k += 1;
            start = i + 1;
            quotes = 0;
        } else if c == b'"' {
            quotes += 1;
        }
    }
    if k + 1 != N {
        return None;
    }
    out[k] = unquote(&line[start..], quotes)?;
    Some(out)
}

/// Byte classes for the one-pass scanner: 1 comma, 2 quote, 3 newline.
static CLASS: [u8; 256] = {
    let mut t = [0u8; 256];
    t[b',' as usize] = 1;
    t[b'"' as usize] = 2;
    t[b'\n' as usize] = 3;
    t
};

/// Parses the line that starts at `*pos` into exactly N fields and moves
/// `*pos` past its '\n'. Returns None for a malformed or empty line. Same
/// result as `fields_fast` on the line `for_lines` would hand it.
#[inline(always)]
fn scan_fields<'a, const N: usize>(buf: &'a [u8], pos: &mut usize) -> Option<[&'a [u8]; N]> {
    let len = buf.len();
    let mut out: [&[u8]; N] = [&[]; N];
    let mut k = 0usize;
    let mut fstart = *pos;
    let mut quotes = 0u32;
    let mut bad = false;
    let mut i = *pos;
    while i < len {
        let cl = CLASS[buf[i] as usize];
        if cl == 0 {
            i += 1;
            continue;
        }
        if cl == 3 {
            break;
        }
        if cl == 1 {
            if !bad {
                if k + 1 >= N {
                    bad = true;
                } else {
                    match unquote(&buf[fstart..i], quotes) {
                        Some(f) => {
                            out[k] = f;
                            k += 1;
                        }
                        None => bad = true,
                    }
                }
            }
            fstart = i + 1;
            quotes = 0;
        } else {
            quotes += 1;
        }
        i += 1;
    }
    *pos = i + 1;
    if bad || k + 1 != N {
        return None;
    }
    out[k] = unquote(&buf[fstart..i], quotes)?;
    Some(out)
}

/// Calls f with the fields of every well-formed line of a chunk.
#[inline(always)]
#[allow(dead_code)]
fn for_records<'a, const N: usize>(buf: &'a [u8], mut f: impl FnMut([&'a [u8]; N])) {
    let mut pos = 0usize;
    while pos < buf.len() {
        if let Some(fs) = scan_fields::<N>(buf, &mut pos) {
            f(fs);
        }
    }
}

/// Splits one line into exactly N fields under the rules' dialect.
/// Returns None for a malformed line. Quotes around a whole field are
/// stripped; any other quote makes the line malformed.
#[inline]
#[allow(dead_code)]
fn fields<const N: usize>(line: &[u8]) -> Option<[&[u8]; N]> {
    let mut out: [&[u8]; N] = [&[]; N];
    let mut start = 0usize;
    let mut k = 0usize;
    let len = line.len();
    let mut i = 0usize;
    loop {
        // find the end of this field
        let end = match memchr::memchr(b',', &line[i..]) {
            Some(p) => i + p,
            None => len,
        };
        if k >= N {
            return None;
        }
        let f = &line[start..end];
        out[k] = if let Some(q) = memchr::memchr(b'"', f) {
            if q != 0 || f.len() < 2 || f[f.len() - 1] != b'"' {
                return None;
            }
            let inner = &f[1..f.len() - 1];
            if memchr::memchr(b'"', inner).is_some() {
                return None;
            }
            inner
        } else {
            f
        };
        k += 1;
        if end == len {
            break;
        }
        start = end + 1;
        i = start;
    }
    if k != N {
        return None;
    }
    Some(out)
}

/// Calls f on every data line of a chunk (lines end at '\n' only).
#[inline]
fn for_lines<'a>(buf: &'a [u8], mut f: impl FnMut(&'a [u8])) {
    let mut pos = 0;
    while pos < buf.len() {
        let end = match memchr::memchr(b'\n', &buf[pos..]) {
            Some(p) => pos + p,
            None => buf.len(),
        };
        let line = &buf[pos..end];
        if !line.is_empty() {
            f(line);
        }
        pos = end + 1;
    }
}

// ------------------------------------------------------------------ time

#[inline]
fn d2(b: &[u8], i: usize) -> Option<i64> {
    let a = b[i].wrapping_sub(b'0');
    let c = b[i + 1].wrapping_sub(b'0');
    if a > 9 || c > 9 {
        return None;
    }
    Some((a * 10 + c) as i64)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// F1 / F2 / F3 to epoch milliseconds, or None for a bad timestamp
/// (the window is checked by the caller). F3 values too large for i64 are
/// returned as i64::MAX (outside any window).
#[inline]
fn parse_ts(b: &[u8]) -> Option<i64> {
    let n = b.len();
    if n == 0 {
        return None;
    }
    if n == 20 || n == 25 {
        if b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':' {
            let y = d2(b, 0)? * 100 + d2(b, 2)?;
            let mo = d2(b, 5)?;
            let d = d2(b, 8)?;
            let h = d2(b, 11)?;
            let mi = d2(b, 14)?;
            let s = d2(b, 17)?;
            if !(1..=12).contains(&mo) || h > 23 || mi > 59 || s > 59 || d < 1 {
                return None;
            }
            let dim = match mo {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                _ => {
                    if is_leap(y) {
                        29
                    } else {
                        28
                    }
                }
            };
            if d > dim {
                return None;
            }
            let mut ms = (days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s) * 1000;
            if n == 20 {
                if b[19] != b'Z' {
                    return None;
                }
            } else {
                let sign = match b[19] {
                    b'+' => 1,
                    b'-' => -1,
                    _ => return None,
                };
                if b[22] != b':' {
                    return None;
                }
                let oh = d2(b, 20)?;
                let om = d2(b, 23)?;
                if oh > 23 || om > 59 {
                    return None;
                }
                ms -= sign * (oh * 3600 + om * 60) * 1000;
            }
            return Some(ms);
        }
    }
    // F3: digits only. Up to 18 digits cannot overflow an i64.
    if n <= 18 {
        let mut v: i64 = 0;
        for &c in b {
            let d = c.wrapping_sub(b'0');
            if d > 9 {
                return None;
            }
            v = v * 10 + d as i64;
        }
        return Some(v);
    }
    let mut v: i64 = 0;
    let mut big = false;
    for &c in b {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        if !big {
            match v.checked_mul(10).and_then(|x| x.checked_add(d as i64)) {
                Some(x) => v = x,
                None => big = true,
            }
        }
    }
    Some(if big { i64::MAX } else { v })
}

// ------------------------------------------------------------------ files

struct Chunk {
    file: usize,
    start: usize,
    end: usize,
}

fn list_csv(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "csv").unwrap_or(false))
            .collect(),
        Err(_) => vec![],
    };
    v.sort();
    v
}

fn map_files(paths: &[PathBuf]) -> Vec<Option<Mmap>> {
    paths
        .par_iter()
        .map(|p| {
            let f = File::open(p).ok()?;
            let len = f.metadata().ok()?.len();
            if len == 0 {
                return None;
            }
            let m = unsafe { Mmap::map(&f).ok()? };
            #[cfg(unix)]
            {
                let _ = m.advise(memmap2::Advice::Sequential);
                // optional: start reading the whole file now, in case it is not cached
                if std::env::var_os("SS_WILLNEED").is_some() {
                    let _ = m.advise(memmap2::Advice::WillNeed);
                }
            }
            Some(m)
        })
        .collect()
}

fn chunks(maps: &[Option<Mmap>], target: usize) -> Vec<Chunk> {
    let mut out = vec![];
    for (fi, m) in maps.iter().enumerate() {
        let Some(m) = m else { continue };
        let b: &[u8] = m;
        // skip header
        let Some(h) = memchr::memchr(b'\n', b) else { continue };
        let mut s = h + 1;
        while s < b.len() {
            let mut e = (s + target).min(b.len());
            if e < b.len() {
                e = match memchr::memchr(b'\n', &b[e..]) {
                    Some(p) => e + p + 1,
                    None => b.len(),
                };
            }
            out.push(Chunk { file: fi, start: s, end: e });
            s = e;
        }
    }
    out
}

// ------------------------------------------------------------------ string refs

/// A string inside a mapped input file, packed as ptr << 16 | len. A string
/// of 0xFFFF bytes or more is copied to a leaked buffer that starts with its
/// length (never happens with the generator's data, but stays exact).
#[inline]
fn pack(s: &[u8]) -> u64 {
    let p = s.as_ptr() as u64;
    if s.len() < 0xFFFF && p < (1u64 << 48) {
        (p << 16) | s.len() as u64
    } else {
        let mut v = (s.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(s);
        let q = Box::leak(v.into_boxed_slice()).as_ptr() as u64;
        (q << 16) | 0xFFFF
    }
}

#[inline]
fn unpack<'a>(r: u64) -> &'a [u8] {
    let ptr = (r >> 16) as usize as *const u8;
    let len = (r & 0xFFFF) as usize;
    unsafe {
        if len < 0xFFFF {
            std::slice::from_raw_parts(ptr, len)
        } else {
            let mut b = [0u8; 8];
            std::ptr::copy_nonoverlapping(ptr, b.as_mut_ptr(), 8);
            std::slice::from_raw_parts(ptr.add(8), u64::from_le_bytes(b) as usize)
        }
    }
}

// ------------------------------------------------------------------ link table

/// Open-addressing table from an ID hash to its person key, 16 bytes a slot so
/// a slot never spans two cache lines, with person names in a side array.
/// Keys are hashes, so the low bits index slots. Key 0 marks empty.
struct LinkTable {
    n: usize,
    mask: usize,
    slots: Vec<(u64, u64)>,
    names: Vec<u64>,
}

impl LinkTable {
    fn cap_for(n: usize) -> usize {
        ((n * 8 / 5).max(16)).next_power_of_two()
    }
    fn new(n: usize) -> Self {
        let cap = Self::cap_for(n);
        LinkTable { n: 0, mask: cap - 1, slots: vec![(0, 0); cap], names: vec![0; cap] }
    }
    #[inline(always)]
    fn fix(k: u64) -> u64 {
        if k == 0 { 0x9e37_79b9_7f4a_7c15 } else { k }
    }
    fn insert(&mut self, k: u64, pk: u64, nref: u64) {
        let k = Self::fix(k);
        let mut i = (k as usize) & self.mask;
        loop {
            let s = &mut self.slots[i];
            if s.0 == 0 || s.0 == k {
                *s = (k, pk);
                self.names[i] = nref;
                return;
            }
            i = (i + 1) & self.mask;
        }
    }
    /// The slot of an ID, probed one table slice at a time by the callers, so
    /// the slots are already in cache.
    #[inline]
    fn slot_direct(&self, k: u64) -> Option<usize> {
        let k = Self::fix(k);
        let mut i = (k as usize) & self.mask;
        loop {
            let s = &self.slots[i];
            if s.0 == k {
                return Some(i);
            }
            if s.0 == 0 {
                return None;
            }
            i = (i + 1) & self.mask;
        }
    }
    #[inline]
    fn get_direct(&self, k: u64) -> Option<u64> {
        self.slot_direct(k).map(|i| self.slots[i].1)
    }
}

/// Which slice of the link table an ID hash probes first. Records are grouped
/// by slice while parsing, so person lookups later walk one slice at a time
/// and find its slots in cache instead of in memory.
#[derive(Clone, Copy)]
struct Lb {
    mask: usize,
    shift: u32,
}
impl Lb {
    #[inline(always)]
    fn of(self, k: u64) -> usize {
        ((LinkTable::fix(k) as usize) & self.mask) >> self.shift
    }
}

// ------------------------------------------------------------------ records

/// One parsed (non-malformed) event copy, kept in file order. `uref` is 0
/// unless the copy is valid and not late, so the event counts only if this is
/// the kept copy and `uref != 0`.
#[derive(Clone, Copy)]
struct Rec {
    uh: u64, // user_id hash
    // user_id offset in its chunk (24 bits; for long IDs, an index into the
    // chunk's long-ID list) | length (7 bits, 127 = long) << 24 | purchase
    // flag << 31 | ts (ms since window start) << 32. A purchase's (price,
    // category) is the next entry of the chunk's per-slice purchase list.
    w: u64,
}

/// The dedup key of one copy, 16 bytes: 64 bits of the event_id hash (its
/// bucket fixes more bits), and `w` = ingest offset (40 bits, ms from
/// window_start - 2^39) << 24 | record position (24 bits: slice << pbits | pos,
/// all ones for a copy that has no record). Generator ingest times lie within
/// days of the window, far inside the 40-bit range; an unparseable ingest
/// takes the top value, so it sorts after every real one.
#[derive(Clone, Copy)]
struct Key {
    e0: u64,
    w: u64,
}

const NOREC: u64 = 0xFF_FFFF;

/// Set when a record position does not fit its bits; main then reruns
/// itself with smaller chunks.
static POS_OVERFLOW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A surviving event, routed to its person's partition.
#[derive(Clone, Copy)]
struct EvP {
    pk: u64,
    nref: u64,
    ts: u32,
    // 0, or for a purchase: routing group << 24 | (index + 1) into that group's purchases
    aux: u32,
}

/// A valid click, routed to its person's partition.
#[derive(Clone, Copy)]
struct ClP {
    pk: u64,
    cid: u64,
    ts: u32, // ms since window start - 7 days
    camp: u32,
}

/// Timing experiments only (wrong output): 1 = scan only, 2 = no record or
/// key writes, 3 = no timestamp parsing, 4 = no hashing.
static PMODE: std::sync::LazyLock<u8> =
    std::sync::LazyLock::new(|| std::env::var("SS_PMODE").ok().and_then(|v| v.parse().ok()).unwrap_or(0));
const PB: u32 = 11; // person partitions = 1 << PB (by person key); about 9k rows each at 20M, so a partition stays in L2
const NP: usize = 1 << PB;

#[inline]
fn part_of(pk: u64) -> usize {
    (pk >> (64 - PB)) as usize
}

/// Byte-string map keyed by xxh3 with an exact key check.
struct StrMap<V: Copy> {
    m: IdMap<(V, u64)>,
}
impl<V: Copy> StrMap<V> {
    fn new() -> Self {
        StrMap { m: IdMap::default() }
    }
    fn insert_first(&mut self, k: &[u8], v: V) -> bool {
        let h = xxh3_64(k);
        if let Some(&(_, r)) = self.m.get(&h) {
            if unpack(r) != k {
                panic!("hash collision in a small table");
            }
            return false;
        }
        self.m.insert(h, (v, pack(k)));
        true
    }
    #[inline]
    fn get(&self, k: &[u8]) -> Option<V> {
        match self.m.get(&xxh3_64(k)) {
            Some(&(v, r)) if unpack(r) == k => Some(v),
            _ => None,
        }
    }
}

/// Sorts a group by a key of at most 96 bits (high bits first) plus the
/// row index, using the primitive sort on u128 keys, then permutes the rows.
fn keyed_sort<T: Copy>(g: &mut [T], key: impl Fn(&T) -> u128, keys: &mut Vec<u128>, tmp: &mut Vec<T>) {
    keys.clear();
    keys.extend(g.iter().enumerate().map(|(i, x)| (key(x) << 32) | i as u128));
    keys.sort_unstable();
    tmp.clear();
    tmp.extend(keys.iter().map(|&k| g[(k as u32) as usize]));
    g.copy_from_slice(tmp);
}

/// Sorts a group of person rows by (person, time) with u64 keys: each of the
/// group's few people gets a rank, and rank << 52 | ts << 20 | row index sorts
/// in the same order. Groups with over 64 people or 2^20 rows use u128 keys.
fn sort_evp(g: &mut [EvP], keys: &mut Vec<u64>, wide: &mut Vec<u128>, tmp: &mut Vec<EvP>) {
    let mut pks = [0u64; 64];
    let mut np = 0usize;
    let mut fits = g.len() < (1 << 20);
    for e in g.iter() {
        if !pks[..np].contains(&e.pk) {
            if np == 64 {
                fits = false;
                break;
            }
            pks[np] = e.pk;
            np += 1;
        }
    }
    if !fits {
        keyed_sort(g, |e| ((e.pk as u128) << 32) | e.ts as u128, wide, tmp);
        return;
    }
    pks[..np].sort_unstable();
    keys.clear();
    keys.extend(g.iter().enumerate().map(|(i, e)| {
        let r = if np == 1 { 0 } else { pks[..np].partition_point(|&p| p < e.pk) as u64 };
        (r << 52) | ((e.ts as u64) << 20) | i as u64
    }));
    keys.sort_unstable();
    tmp.clear();
    tmp.extend(keys.iter().map(|&k| g[(k & 0xF_FFFF) as usize]));
    g.copy_from_slice(tmp);
}

/// Gathers the slices into `out` in the order of `less`, which must order by
/// the person key first. A counting pass on the `sb` key bits right below the
/// partition bits splits the rows into small groups, then each group gets an
/// insertion sort. Returns the row count.
fn group_sort<'a, T: Copy + 'a, I: Iterator<Item = &'a [T]> + Clone>(
    src: I,
    sb: u32,
    key: impl Fn(&T) -> u64,
    less: impl Fn(&T, &T) -> bool,
    mut by_rest: impl FnMut(&mut [T]),
    mut many: impl FnMut(&mut [T]),
    cnt: &mut [u32],
    out: &mut Vec<T>,
) -> usize {
    let ng = 1usize << sb;
    let sub = |x: &T| ((key(x) << PB) >> (64 - sb)) as usize;
    cnt[..ng + 1].fill(0);
    let mut n = 0usize;
    for s in src.clone() {
        n += s.len();
        for x in s {
            cnt[sub(x) + 1] += 1;
        }
    }
    out.clear();
    if n == 0 {
        return 0;
    }
    for b in 0..ng {
        cnt[b + 1] += cnt[b];
    }
    out.reserve(n);
    let dst = out.as_mut_ptr();
    for s in src {
        for x in s {
            let b = sub(x);
            unsafe { dst.add(cnt[b] as usize).write(*x) };
            cnt[b] += 1;
        }
    }
    unsafe { out.set_len(n) };
    // cnt[b] is now the end of group b
    let mut lo = 0usize;
    for b in 0..ng {
        let hi = cnt[b] as usize;
        if hi - lo > 1 {
            let g = &mut out[lo..hi];
            if g.len() <= 32 {
                for i in 1..g.len() {
                    let x = g[i];
                    let mut j = i;
                    while j > 0 && less(&x, &g[j - 1]) {
                        g[j] = g[j - 1];
                        j -= 1;
                    }
                    g[j] = x;
                }
            } else if key(&g[0]) == key(&g[g.len() - 1]) && g.iter().all(|x| key(x) == key(&g[0])) {
                // one person, often a heavy one: sort on the rest of the key
                by_rest(g);
            } else {
                many(g);
            }
        }
        lo = hi;
    }
    n
}

// ------------------------------------------------------------------ phases

/// Joins every link line into people and returns the table from an ID hash
/// to (person key, person name). The person key is the hash of the person's
/// byte-wise smallest ID, and the name points at that ID's bytes.
/// One link line: both ID hashes and both ID byte refs.
type LinkPair = (u64, u64, u64, u64);

/// Parallel part of linking: parse link lines, and sort every line end by its
/// ID hash, keeping where it came from (2 * line + side).
fn link_ids(maps: &[Option<Mmap>], chunks: &[Chunk]) -> (Vec<LinkPair>, Vec<(u64, u32)>, usize) {
    let pairs: Vec<LinkPair> = chunks
        .par_iter()
        .flat_map_iter(|c| {
            let b: &[u8] = maps[c.file].as_ref().unwrap();
            let buf = &b[c.start..c.end];
            let mut v = Vec::new();
            scan::for_records::<2>(buf, |[a, bb]| {
                if a.is_empty() || bb.is_empty() {
                    return;
                }
                v.push((xxh3_64(a), xxh3_64(bb), pack(a), pack(bb)));
            });
            v
        })
        .collect();
    let mut ends: Vec<(u64, u32)> =
        (0..pairs.len()).into_par_iter().flat_map_iter(|i| [(pairs[i].0, 2 * i as u32), (pairs[i].1, 2 * i as u32 + 1)]).collect();
    ends.par_sort_unstable_by_key(|x| x.0);
    let n_ids = if ends.is_empty() { 0 } else { ends.par_windows(2).filter(|w| w[0].0 != w[1].0).count() + 1 };
    (pairs, ends, n_ids)
}

/// Sequential part of linking: dense IDs from the sorted line ends, union-find,
/// and the final lookup table. Runs on its own thread while the pool parses.
fn link_table(pairs: Vec<LinkPair>, ends: Vec<(u64, u32)>) -> LinkTable {
    // dense index of each line end, and (hash, name ref) of each distinct ID
    let mut dense_of = vec![0u32; ends.len()];
    let mut ids: Vec<(u64, u64)> = Vec::with_capacity(ends.len() / 2 + 1);
    for (j, &(h, slot)) in ends.iter().enumerate() {
        if j == 0 || ends[j - 1].0 != h {
            let p = &pairs[(slot / 2) as usize];
            ids.push((h, if slot % 2 == 0 { p.2 } else { p.3 }));
        }
        dense_of[slot as usize] = (ids.len() - 1) as u32;
    }
    let n_ids = ids.len();
    let mut parent: Vec<u32> = (0..n_ids as u32).collect();
    fn find(p: &mut [u32], mut x: u32) -> u32 {
        while p[x as usize] != x {
            let g = p[p[x as usize] as usize];
            p[x as usize] = g;
            x = g;
        }
        x
    }
    for i in 0..pairs.len() {
        let ra = find(&mut parent, dense_of[2 * i]);
        let rb = find(&mut parent, dense_of[2 * i + 1]);
        if ra != rb {
            // the root keeps the byte-wise smaller name, so roots name people
            if unpack(ids[ra as usize].1) <= unpack(ids[rb as usize].1) {
                parent[rb as usize] = ra;
            } else {
                parent[ra as usize] = rb;
            }
        }
    }
    let mut link = LinkTable::new(n_ids);
    for i in 0..n_ids as u32 {
        let r = find(&mut parent, i) as usize;
        link.insert(ids[i as usize].0, ids[r].0, ids[r].1);
    }
    link.n = n_ids;
    link
}

/// Parses every event file: records in file order per chunk, and their dedup
/// keys in buckets by the event_id hash. Persons are resolved after dedup.
fn parse_events(
    maps: &[Option<Mmap>],
    chunks: &[Chunk],
    ws: i64,
    we: i64,
    prod: &StrMap<u16>,
    unknown_cat: u16,
    nb: usize,
    lb: Lb,
    nlb: usize,
    pbits: u32,
) -> Vec<(Vec<Vec<Rec>>, Vec<Vec<Key>>, Vec<Vec<(u32, u16)>>, Vec<u64>)> {
    chunks
        .par_iter()
        .map(|c| {
            let b: &[u8] = maps[c.file].as_ref().unwrap();
            let buf = &b[c.start..c.end];
            // records die after routing: scratch region 2
            bump::select(2);
            let mut recs: Vec<Vec<Rec>> = (0..nlb).map(|_| Vec::with_capacity(buf.len() / 70 / nlb + 16)).collect();
            bump::select(0);
            let mut purch: Vec<Vec<(u32, u16)>> = (0..nlb).map(|_| Vec::new()).collect();
            let mut long_ids: Vec<u64> = Vec::new();
            let cbase = buf.as_ptr() as usize;
            // dedup keys die after dedup, so they live in the scratch region
            bump::select(1);
            let mut buckets: Vec<Vec<Key>> = (0..nb).map(|_| Vec::with_capacity(buf.len() / 70 / nb + 8)).collect();
            bump::select(0);
            let mut rswc: swc::Swc<Rec> = swc::Swc::new(nlb);
            let mut kswc: swc::Swc<Key> = swc::Swc::new(nb);
            let pmode = *PMODE;
            scan::for_records::<7>(buf, |[eid, uid, ts, ing, typ, pid, price]| {
                if pmode == 1 {
                    std::hint::black_box((eid.len(), uid.len(), ts.len(), ing.len(), typ.len(), pid.len(), price.len()));
                    return;
                }
                if eid.is_empty() {
                    return;
                }
                let h = if pmode == 4 { eid.len() as u128 * 0x9e37_79b9_7f4a_7c15 } else { xxh3_128(eid) };
                let ingest = if pmode == 3 { ws + ing.len() as i64 } else { crate::ts::parse_ts(ing).unwrap_or(i64::MAX) };
                let mut ok = !uid.is_empty() && !pid.is_empty();
                let tsv = match if pmode == 3 { Some(ws + ts.len() as i64) } else { crate::ts::parse_ts(ts) } {
                    Some(t) if t >= ws && t < we => (t - ws) as u32,
                    _ => {
                        ok = false;
                        0
                    }
                };
                let mut pr = 0u32;
                let mut cat = 0u16;
                match typ {
                    b"view" | b"cart" => {}
                    b"purchase" => {
                        let mut v: u64 = 0;
                        let mut good = !price.is_empty();
                        for &ch in price {
                            let d = ch.wrapping_sub(b'0');
                            if d > 9 {
                                good = false;
                                break;
                            }
                            v = v * 10 + d as u64;
                            if v > 10_000_000 {
                                good = false;
                                break;
                            }
                        }
                        if !good || v == 0 {
                            ok = false;
                        } else {
                            pr = v as u32;
                            cat = prod.get(pid).unwrap_or(unknown_cat);
                        }
                    }
                    _ => ok = false,
                }
                // the late rule needs only this copy's own times
                let keep = ok && ingest - (tsv as i64 + ws) <= DAY;
                // only a copy that would count is stored; others need just a dedup key
                let rix = if keep {
                    let uh = if pmode == 4 { uid.len() as u64 * 0x9e37_79b9_7f4a_7c15 } else { xxh3_64(uid) };
                    let b = lb.of(uh);
                    if pr > 0 {
                        purch[b].push((pr, cat));
                    }
                    let (off, len) = if uid.len() < 127 {
                        ((uid.as_ptr() as usize - cbase) as u64, uid.len() as u64)
                    } else {
                        long_ids.push(pack(uid));
                        ((long_ids.len() - 1) as u64, 127)
                    };
                    let w = off | len << 24 | ((pr > 0) as u64) << 31 | (tsv as u64) << 32;
                    let pos = (recs[b].len() + rswc.pending(b)) as u64;
                    if pmode == 2 {
                        std::hint::black_box((uh, w));
                    } else {
                        rswc.push(&mut recs, b, Rec { uh, w });
                    }
                    let rix = ((b as u64) << pbits) | pos;
                    if pos >= (1 << pbits) - 1 || rix >= NOREC {
                        POS_OVERFLOW.store(true, Ordering::Relaxed);
                    }
                    rix & NOREC
                } else {
                    NOREC
                };
                let ing40 = if ingest == i64::MAX { (1u64 << 40) - 1 } else { (ingest - (ws - (1i64 << 39))).clamp(0, (1i64 << 40) - 2) as u64 };
                if pmode == 2 {
                    std::hint::black_box((h, ing40, rix));
                } else {
                    kswc.push(&mut buckets, (h >> 64) as usize & (nb - 1), Key { e0: h as u64, w: (ing40 << 24) | rix });
                }
            });
            rswc.finish(&mut recs);
            kswc.finish(&mut buckets);
            (recs, buckets, purch, long_ids)
        })
        .collect()
}

/// Parses every click file into one vector per chunk. `pk` holds the user
/// hash until the link table resolves it to the person.
fn parse_clicks(
    maps: &[Option<Mmap>],
    chunks: &[Chunk],
    cbase: i64,
    we: i64,
    camp: &StrMap<u32>,
    lb: Lb,
    nlb: usize,
) -> Vec<Vec<Vec<ClP>>> {
    chunks
        .par_iter()
        .map(|c| {
            let b: &[u8] = maps[c.file].as_ref().unwrap();
            let buf = &b[c.start..c.end];
            // raw clicks die once routed: scratch region 2
            bump::select(2);
            let mut v: Vec<Vec<ClP>> = (0..nlb).map(|_| Vec::with_capacity(buf.len() / 45 / nlb + 16)).collect();
            bump::select(0);
            let mut cswc: swc::Swc<ClP> = swc::Swc::new(nlb);
            scan::for_records::<4>(buf, |[cid, uid, cmp, ts]| {
                if cid.is_empty() || uid.is_empty() {
                    return;
                }
                let Some(t) = crate::ts::parse_ts(ts) else { return };
                if t < cbase || t >= we {
                    return;
                }
                let Some(ci) = camp.get(cmp) else { return };
                let uh = xxh3_64(uid);
                cswc.push(&mut v, lb.of(uh), ClP { pk: uh, cid: pack(cid), ts: (t - cbase) as u32, camp: ci });
            });
            cswc.finish(&mut v);
            v
        })
        .collect()
}

fn stamp(what: &str) {
    if std::env::var_os("SS_STAMP").is_some() {
        let ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        eprintln!("stamp {what} {ns}");
    }
}

fn main() {
    stamp("start");
    bump::init();
    let t0 = Instant::now();
    let data = PathBuf::from(std::env::var("DATA_DIR").unwrap_or("/data".into()));
    let out = PathBuf::from(std::env::var("OUTPUT_DIR").unwrap_or("/output".into()));
    let ncpu: usize = std::env::var("NCPU").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
    rayon::ThreadPoolBuilder::new().num_threads(ncpu).build_global().ok();

    // manifest
    let man = std::fs::read_to_string(data.join("manifest.json")).expect("manifest");
    let grab = |k: &str| -> i64 {
        let i = man.find(k).expect("key") + k.len();
        let rest = &man[i..];
        let q1 = rest.find('"').unwrap();
        let rest = &rest[q1 + 1..];
        let q2 = rest.find('"').unwrap();
        parse_ts(rest[..q2].as_bytes()).expect("manifest ts")
    };
    let ws = grab("\"window_start\"");
    let we = grab("\"window_end\"");
    let cbase = ws - WEEK;

    // map files first so the kernel can start reading while we build tables
    let ev_paths = list_csv(&data.join("events"));
    let cl_paths = list_csv(&data.join("clicks"));
    let ln_paths = list_csv(&data.join("links"));
    let ev_maps = map_files(&ev_paths);
    let cl_maps = map_files(&cl_paths);
    let ln_maps = map_files(&ln_paths);


    // dedup buckets of about 40k copies keep each bucket's table in L2; chunks
    // grow with the bucket count so each chunk still fills its buckets
    let ev_bytes: usize = ev_maps.iter().map(|m| m.as_ref().map_or(0, |m| m.len())).sum();
    let nb = std::env::var("SS_NB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| v.is_power_of_two())
        .unwrap_or_else(|| (ev_bytes / 76 / 40_000).next_power_of_two().clamp(256, 4096));
    // event chunks stay under 16 MB so record name offsets fit 24 bits
    let chunk_div: usize = std::env::var("SS_CHUNKDIV").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let ev_chunks = chunks(&ev_maps, ((4usize << 20) * nb / 512).min((16 << 20) - (1 << 16)) / chunk_div);
    let ev_chunks_base: Vec<usize> =
        ev_chunks.iter().map(|c| ev_maps[c.file].as_ref().map_or(0, |m| m.as_ptr() as usize + c.start)).collect();
    let ev_chunks_base = &ev_chunks_base;
    let cl_chunks = chunks(&cl_maps, 4 << 20);


    // ---------------- links on one worker, overlapped with parsing events and clicks
    // the small product and campaign tables load while the pool parses link lines
    let ln_chunks = chunks(&ln_maps, 1 << 20);
    let (tables, (ln_pairs, ln_ends, n_ids)) = rayon::join(
        || {
        // products and campaigns (small, clean); the raw buffers live to the end
        let prod_raw: &'static [u8] = Box::leak(std::fs::read(data.join("products.csv")).unwrap_or_default().into_boxed_slice());
        let camp_raw: &'static [u8] = Box::leak(std::fs::read(data.join("campaigns.csv")).unwrap_or_default().into_boxed_slice());
        let mut cat_names: Vec<Vec<u8>> = vec![];
        let mut cat_idx: HashMap<Vec<u8>, u16> = HashMap::new();
        let mut prod: StrMap<u16> = StrMap::new();
        {
            let body = match memchr::memchr(b'\n', prod_raw) {
                Some(h) => &prod_raw[h + 1..],
                None => &prod_raw[0..0],
            };
            for_lines(body, |l| {
                if let Some([p, c]) = fields_fast::<2>(l) {
                    let n = cat_idx.len() as u16;
                    let ci = *cat_idx.entry(c.to_vec()).or_insert_with(|| {
                        cat_names.push(c.to_vec());
                        n
                    });
                    prod.insert_first(p, ci);
                }
            });
        }
        let unknown_cat = match cat_idx.get(&b"unknown"[..]) {
            Some(&c) => c,
            None => {
                cat_names.push(b"unknown".to_vec());
                (cat_names.len() - 1) as u16
            }
        };
        let ncat = cat_names.len();
        let mut order: Vec<usize> = (0..ncat).collect();
        order.sort_by(|a, b| cat_names[*a].cmp(&cat_names[*b]));
        let mut cat_rank = vec![0usize; ncat];
        for (r, &c) in order.iter().enumerate() {
            cat_rank[c] = r;
        }

        let mut camp_names: Vec<Vec<u8>> = vec![];
        let mut camp_chan: Vec<Vec<u8>> = vec![];
        let mut camp: StrMap<u32> = StrMap::new();
        {
            let body = match memchr::memchr(b'\n', camp_raw) {
                Some(h) => &camp_raw[h + 1..],
                None => &camp_raw[0..0],
            };
            for_lines(body, |l| {
                if let Some([c, ch]) = fields_fast::<2>(l) {
                    if camp.insert_first(c, camp_names.len() as u32) {
                        camp_names.push(c.to_vec());
                        camp_chan.push(ch.to_vec());
                    }
                }
            });
        }
        let organic = camp_names.len() as u32;
        camp_names.push(b"organic".to_vec());
        camp_chan.push(b"organic".to_vec());
        let ncamp = camp_names.len();
            (cat_names, prod, unknown_cat, ncat, cat_rank, camp_names, camp_chan, camp, organic, ncamp)
        },
        || link_ids(&ln_maps, &ln_chunks),
    );
    let (cat_names, prod, unknown_cat, ncat, cat_rank, camp_names, camp_chan, camp, organic, ncamp) = tables;
    log!("tables and link ids {:?}", t0.elapsed());
    // slices of 32k slots (512 KB), at most 256 of them
    let lcap = LinkTable::cap_for(n_ids);
    let lbits = (lcap.trailing_zeros() as i32 - 15).clamp(0, 8) as u32;
    let nlb = 1usize << lbits;
    let lb = Lb { mask: lcap - 1, shift: lcap.trailing_zeros() - lbits };
    let pbits = 24 - lbits;
    log!("link ids {:?}", t0.elapsed());
    // the union-find runs on its own thread while the pool parses events and clicks together
    let link_thread = std::thread::spawn(move || link_table(ln_pairs, ln_ends));
    let (parsed, cl_raw) = rayon::join(
        || parse_events(&ev_maps, &ev_chunks, ws, we, &prod, unknown_cat, nb, lb, nlb, pbits),
        || parse_clicks(&cl_maps, &cl_chunks, cbase, we, &camp, lb, nlb),
    );
    log!("parsed events and clicks {:?}", t0.elapsed());
    if chunk_div == 1 && std::env::var_os("SS_TEST_OVERFLOW").is_some() {
        POS_OVERFLOW.store(true, Ordering::Relaxed);
    }
    if POS_OVERFLOW.load(Ordering::Relaxed) {
        assert!(chunk_div < 64, "record positions overflow even with small chunks");
        // a slice of one chunk held too many records for the key's position
        // bits: run again with chunks a quarter the size
        let div = chunk_div * 4;
        let st = std::process::Command::new(std::env::current_exe().expect("exe")).env("SS_CHUNKDIV", div.to_string()).status().expect("rerun");
        std::process::exit(st.code().unwrap_or(1));
    }
    let mut ev_recs: Vec<Vec<Vec<Rec>>> = Vec::with_capacity(parsed.len());
    let mut ev_keys: Vec<Vec<Vec<Key>>> = Vec::with_capacity(parsed.len());
    let mut ev_purch: Vec<Vec<Vec<(u32, u16)>>> = Vec::with_capacity(parsed.len());
    let mut ev_long: Vec<Vec<u64>> = Vec::with_capacity(parsed.len());
    for (r, k, pu, lg) in parsed {
        ev_long.push(lg);
        ev_recs.push(r);
        ev_keys.push(k);
        ev_purch.push(pu);
    }

    // ---------------- dedup on event_id: mark each copy that is not the kept one.
    // It needs no person data, so it runs while the union-find may still be going.
    let losers: Vec<Vec<Vec<AtomicU64>>> = ev_recs
        .iter()
        .map(|rb| rb.iter().map(|r| (0..r.len().div_ceil(64)).map(|_| AtomicU64::new(0)).collect()).collect())
        .collect();
    let groups = (ncpu * 8).clamp(1, nb);
    let per_g = nb.div_ceil(groups);
    {
        let keys = &ev_keys;
        let losers = &losers;
        (0..groups).into_par_iter().for_each(|g| {
            let lo_b = g * per_g;
            let hi_b = ((g + 1) * per_g).min(nb);
            // a copy without a record would not count anyway
            let mark = |c: usize, w: u64| {
                let rix = w & NOREC;
                if rix != NOREC {
                    let pos = rix & ((1 << pbits) - 1);
                    losers[c][(rix >> pbits) as usize][(pos / 64) as usize].fetch_or(1u64 << (pos % 64), Ordering::Relaxed);
                }
            };
            // Open-addressing table, 8 bytes a slot: fingerprint << 32 | stamp, where
            // stamp = stamp0 + index + 1 and the index counts the bucket's copies in
            // file order. Stamps at or below stamp0 are left from earlier buckets and
            // count as empty, so the table is never cleared. The kept copy has the
            // smallest ingest_ts; copies with equal ones are identical, and the
            // earliest in file order stays.
            let max_n = (lo_b..hi_b).map(|bi| keys.iter().map(|p| p[bi].len()).sum::<usize>()).max().unwrap_or(0);
            let cap = (max_n * 3 / 2).next_power_of_two().max(16);
            let mask = cap - 1;
            let mut table: Vec<u64> = vec![0; cap];
            let mut start: Vec<u32> = Vec::with_capacity(keys.len() + 1);
            let mut base: Vec<*const Key> = Vec::with_capacity(keys.len());
            let mut stamp0 = 0u64;
            for bi in lo_b..hi_b {
                start.clear();
                base.clear();
                let mut n = 0u32;
                for p in keys.iter() {
                    start.push(n);
                    base.push(p[bi].as_ptr());
                    n += p[bi].len() as u32;
                }
                start.push(n);
                if n == 0 {
                    continue;
                }
                let at = |i: u32| -> (&Key, usize) {
                    let c = start.partition_point(|&s| s <= i) - 1;
                    (unsafe { &*base[c].add((i - start[c]) as usize) }, c)
                };
                let mut i = 0u32;
                for (c, p) in keys.iter().enumerate() {
                    for k in p[bi].iter() {
                        let fp = k.e0 >> 32;
                        let me = stamp0 + i as u64 + 1;
                        let mut s = (k.e0 as usize) & mask;
                        loop {
                            let v = table[s];
                            let st = v & 0xFFFF_FFFF;
                            if st <= stamp0 {
                                table[s] = (fp << 32) | me;
                                break;
                            }
                            if v >> 32 == fp {
                                let (w, wc) = at((st - stamp0 - 1) as u32);
                                if w.e0 == k.e0 {
                                    if (k.w >> 24) < (w.w >> 24) {
                                        table[s] = (fp << 32) | me;
                                        mark(wc, w.w);
                                    } else {
                                        mark(c, k.w);
                                    }
                                    break;
                                }
                            }
                            s = (s + 1) & mask;
                        }
                        i += 1;
                    }
                }
                stamp0 += n as u64;
            }
        });
    }
    std::mem::forget(ev_keys);
    // dedup keys are dead: their memory takes the routed clicks and events
    bump::reset(1);
    log!("deduped {:?}", t0.elapsed());

    let link = link_thread.join().expect("link thread");
    let link = &link;
    log!("linked {} ids {:?}", link.n, t0.elapsed());

    // ---------------- clicks: resolve persons one table slice at a time, route to person partitions
    let cl_parts: Vec<Vec<Vec<ClP>>> = (0..nlb)
        .into_par_iter()
        .map(|b| {
            let n: usize = cl_raw.iter().map(|v| v[b].len()).sum();
            let per = n / NP;
            bump::select(1);
            let mut parts: Vec<Vec<ClP>> = (0..NP).map(|_| Vec::with_capacity(per + per / 4 + 8)).collect();
            bump::select(0);
            let mut swc: swc::Swc<ClP> = swc::Swc::new(NP);
            for v in cl_raw.iter() {
                for &c in v[b].iter() {
                    let mut c = c;
                    if let Some(x) = link.get_direct(c.pk) {
                        c.pk = x;
                    }
                    swc.push(&mut parts, part_of(c.pk), c);
                }
            }
            swc.finish(&mut parts);
            parts
        })
        .collect();
    std::mem::forget(cl_raw);
    log!("routed clicks {:?}", t0.elapsed());

    // ---------------- kept events: resolve persons one table slice at a time, route to person partitions
    // heavy users make some slices much larger: start those first
    let mut slice_order: Vec<usize> = (0..nlb).collect();
    slice_order.sort_by_key(|&b| std::cmp::Reverse(ev_recs.iter().map(|r| r[b].len()).sum::<usize>()));
    let routed: Vec<(usize, Vec<Vec<EvP>>, Vec<(u32, u16)>)> = slice_order
        .into_par_iter()
        .map(|b| {
            let mut purch: Vec<(u32, u16)> = Vec::new();
            let n_est: usize = ev_recs.iter().map(|r| r[b].len()).sum();
            bump::select(1);
            let mut parts: Vec<Vec<EvP>> = (0..NP).map(|_| Vec::with_capacity(n_est / NP + n_est / NP / 4 + 8)).collect();
            bump::select(0);
            let mut swc: swc::Swc<EvP> = swc::Swc::new(NP);
            for c in 0..ev_recs.len() {
                let recs = &ev_recs[c][b];
                let lw = &losers[c][b];
                let cp = &ev_purch[c][b];
                let cbase = ev_chunks_base[c];
                let mut pi = 0usize;
                for (i, r) in recs.iter().enumerate() {
                    let has_pur = (r.w >> 31) & 1 != 0;
                    let p = if has_pur {
                        pi += 1;
                        cp[pi - 1]
                    } else {
                        (0, 0)
                    };
                    if (lw[i / 64].load(Ordering::Relaxed) >> (i % 64)) & 1 != 0 {
                        continue;
                    }
                    // linked people carry their name (smallest ID), others their own ID
                    let (pk, nref) = match link.slot_direct(r.uh) {
                        Some(si) => (link.slots[si].1, link.names[si]),
                        None => {
                            let off = (r.w & 0xFF_FFFF) as usize;
                            let len = ((r.w >> 24) & 127) as usize;
                            let nref = if len < 127 {
                                pack(unsafe { std::slice::from_raw_parts((cbase + off) as *const u8, len) })
                            } else {
                                ev_long[c][off]
                            };
                            (r.uh, nref)
                        }
                    };
                    let aux = if has_pur {
                        purch.push(p);
                        ((b as u32) << 24) | purch.len() as u32
                    } else {
                        0
                    };
                    swc.push(&mut parts, part_of(pk), EvP { pk, nref, ts: (r.w >> 32) as u32, aux });
                }
            }
            swc.finish(&mut parts);
            (b, parts, purch)
        })
        .collect();
    let mut dd: Vec<Vec<Vec<EvP>>> = Vec::with_capacity(nlb);
    let mut purchases: Vec<Vec<(u32, u16)>> = (0..nlb).map(|_| Vec::new()).collect();
    for (b, parts, purch) in routed {
        dd.push(parts);
        purchases[b] = purch;
    }
    let purchases = &purchases;
    std::mem::forget(ev_recs);
    // records and raw clicks are dead: their memory takes the sessionize buffers
    bump::reset(2);
    log!("routed events {:?}", t0.elapsed());

    // ---------------- sessionize, attribute, aggregate (parallel by person partitions)
    let ndays = ((we - ws + DAY - 1) / DAY + 1) as usize;
    let day0 = ws.div_euclid(DAY);
    let tmul: usize = std::env::var("SS_TMUL").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let tasks = (ncpu * tmul).clamp(1, NP);
    let per_t = NP.div_ceil(tasks);

    struct Part {
        user_rows: Vec<(u64, i32, u32, u32, u64, i32)>, // name, day, sessions, events, revenue, top cat (-1)
    }
    let dd_ref = &dd;
    let cl_ref = &cl_parts;
    let old_sort = std::env::var_os("SS_OLDSORT").is_some();
    // group bits below the partition bits: about 8 events per group (finer
    // groups measured no faster on x86)
    let n_kept: usize = dd.iter().map(|g| g.iter().map(|v| v.len()).sum::<usize>()).sum();
    let gdiv: usize = std::env::var("SS_GDIV").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let sb = ((n_kept / NP / gdiv).max(1).ilog2()).clamp(4, 18);
    let cat_rank = &cat_rank;
    let ud = out.join("user_daily");
    let cd = out.join("campaign_daily");
    std::fs::create_dir_all(&ud).unwrap();
    std::fs::create_dir_all(&cd).unwrap();
    let ud = &ud;
    let cat_ref = &cat_names;
    let camp_accs: Vec<std::sync::Mutex<Vec<[u64; 4]>>> =
        (0..rayon::current_num_threads().max(1)).map(|_| std::sync::Mutex::new(Vec::new())).collect();
    let camp_accs = &camp_accs;
    let mut task_order: Vec<usize> = (0..tasks).collect();
    task_order.sort_by_key(|&t| {
        std::cmp::Reverse((t * per_t..((t + 1) * per_t).min(NP)).map(|p| dd.iter().map(|g| g[p].len()).sum::<usize>()).sum::<usize>())
    });
    let mut parts: Vec<Part> = task_order
        .into_par_iter()
        .map(|t| {
            bump::select(2);
            // campaign totals per worker thread: tasks on one thread never overlap
            let mut acc_guard = camp_accs[rayon::current_thread_index().unwrap_or(0) % camp_accs.len()].lock().unwrap();
            if acc_guard.is_empty() {
                *acc_guard = vec![[0u64; 4]; ncamp * ndays];
            }
            let camp_acc: &mut Vec<[u64; 4]> = &mut acc_guard;
            let n_task: usize = (t * per_t..((t + 1) * per_t).min(NP)).map(|p| dd_ref.iter().map(|g| g[p].len()).sum::<usize>()).sum();
            let mut rows = Vec::with_capacity(n_task / 6 + 64);
            let mut catrev = vec![0u64; ncat];
            let mut starts: Vec<i64> = Vec::new();
            let mut sess_days: Vec<usize> = Vec::new();
            let mut evs: Vec<EvP> = Vec::new();
            let mut cls: Vec<ClP> = Vec::new();
            let mut byc: Vec<(u32, i64)> = Vec::new();
            let mut cnt: Vec<u32> = vec![0; (1 << sb) + 1];
            let (mut skeys, mut skeys3): (Vec<u64>, Vec<u64>) = (Vec::new(), Vec::new());
            let (mut skeys2, mut skeys4): (Vec<u128>, Vec<u128>) = (Vec::new(), Vec::new());
            let (mut stmp, mut stmp2): (Vec<EvP>, Vec<EvP>) = (Vec::new(), Vec::new());
            for p in t * per_t..((t + 1) * per_t).min(NP) {
                if old_sort {
                    evs.clear();
                    for g in dd_ref.iter() {
                        evs.extend_from_slice(&g[p]);
                    }
                    if evs.is_empty() {
                        continue;
                    }
                    cls.clear();
                    for c in cl_ref.iter() {
                        cls.extend_from_slice(&c[p]);
                    }
                    evs.sort_unstable_by_key(|e| (e.pk, e.ts));
                    cls.sort_unstable_by(|a, b| {
                        (a.pk, a.ts).cmp(&(b.pk, b.ts)).then_with(|| unpack(a.cid).cmp(unpack(b.cid)))
                    });
                } else {
                    let n = group_sort(
                        dd_ref.iter().map(|g| &g[p][..]),
                        sb,
                        |e: &EvP| e.pk,
                        |a: &EvP, b: &EvP| (a.pk, a.ts) < (b.pk, b.ts),
                        |g: &mut [EvP]| sort_evp(g, &mut skeys, &mut skeys2, &mut stmp),
                        |g: &mut [EvP]| sort_evp(g, &mut skeys3, &mut skeys4, &mut stmp2),
                        &mut cnt,
                        &mut evs,
                    );
                    if n == 0 {
                        continue;
                    }
                    group_sort(
                        cl_ref.iter().map(|c| &c[p][..]),
                        sb,
                        |c: &ClP| c.pk,
                        |a: &ClP, b: &ClP| {
                            (a.pk, a.ts).cmp(&(b.pk, b.ts)).then_with(|| unpack(a.cid).cmp(unpack(b.cid)))
                                == std::cmp::Ordering::Less
                        },
                        |g: &mut [ClP]| g.sort_unstable_by(|a, b| a.ts.cmp(&b.ts).then_with(|| unpack(a.cid).cmp(unpack(b.cid)))),
                        |g: &mut [ClP]| {
                            g.sort_unstable_by(|a, b| {
                                (a.pk, a.ts).cmp(&(b.pk, b.ts)).then_with(|| unpack(a.cid).cmp(unpack(b.cid)))
                            })
                        },
                        &mut cnt,
                        &mut cls,
                    );
                }
                let mut ci = 0usize;
                let mut i = 0usize;
                while i < evs.len() {
                    let person = evs[i].pk;
                    let name = evs[i].nref;
                    let mut j = i + 1;
                    while j < evs.len() && evs[j].pk == person {
                        j += 1;
                    }
                    while ci < cls.len() && cls[ci].pk < person {
                        ci += 1;
                    }
                    let mut cj = ci;
                    while cj < cls.len() && cls[cj].pk == person {
                        cj += 1;
                    }
                    let pcl = &cls[ci..cj];
                    starts.clear();
                    sess_days.clear();
                    let mut cur_day: i64 = i64::MIN;
                    let mut d_sess = 0u32;
                    let mut d_events = 0u32;
                    let mut d_rev = 0u64;
                    let mut d_any = false;
                    let flush = |rows: &mut Vec<(u64, i32, u32, u32, u64, i32)>,
                                 catrev: &mut Vec<u64>,
                                 day: i64,
                                 s: u32,
                                 e: u32,
                                 r: u64,
                                 any: bool| {
                        let top = if any {
                            let mut best: i32 = -1;
                            let mut bv = 0u64;
                            for c in 0..ncat {
                                let v = catrev[c];
                                if v == 0 {
                                    continue;
                                }
                                if best < 0 || v > bv || (v == bv && cat_rank[c] < cat_rank[best as usize]) {
                                    best = c as i32;
                                    bv = v;
                                }
                            }
                            best
                        } else {
                            -1
                        };
                        rows.push((name, day as i32, s, e, r, top));
                        if any {
                            for x in catrev.iter_mut() {
                                *x = 0;
                            }
                        }
                    };
                    let mut k = i;
                    while k < j {
                        let start = evs[k].ts as i64 + ws;
                        let mut last = start;
                        let mut m = k;
                        let mut n_ev = 0u32;
                        let mut rev = 0u64;
                        let mut purch = false;
                        let day = start.div_euclid(DAY);
                        if day != cur_day {
                            if cur_day != i64::MIN {
                                flush(&mut rows, &mut catrev, cur_day, d_sess, d_events, d_rev, d_any);
                            }
                            cur_day = day;
                            d_sess = 0;
                            d_events = 0;
                            d_rev = 0;
                            d_any = false;
                        }
                        while m < j {
                            let tt = evs[m].ts as i64 + ws;
                            if tt - last > MIN30 {
                                break;
                            }
                            last = tt;
                            n_ev += 1;
                            let aux = evs[m].aux;
                            if aux != 0 {
                                let (pr, ct) = purchases[(aux >> 24) as usize][((aux & 0xFF_FFFF) - 1) as usize];
                                let price = pr as u64;
                                rev += price;
                                purch = true;
                                catrev[ct as usize] += price;
                            }
                            m += 1;
                        }
                        d_sess += 1;
                        d_events += n_ev;
                        d_rev += rev;
                        d_any |= purch;
                        // credit: latest click with ts <= start, within 7 days; ties -> smallest click_id
                        let st_off = (start - cbase) as u32;
                        let idx = pcl.partition_point(|c| c.ts <= st_off);
                        let mut credited = organic;
                        if idx > 0 {
                            let tmax = pcl[idx - 1].ts;
                            if (st_off - tmax) as i64 <= WEEK {
                                let f = pcl[..idx].partition_point(|c| c.ts < tmax);
                                credited = pcl[f].camp;
                            }
                        }
                        let di = (day - day0) as usize;
                        let a = &mut camp_acc[credited as usize * ndays + di];
                        a[0] += 1;
                        if purch {
                            a[1] += 1;
                        }
                        a[2] += rev;
                        starts.push(start);
                        sess_days.push(di);
                        k = m;
                    }
                    if cur_day != i64::MIN {
                        flush(&mut rows, &mut catrev, cur_day, d_sess, d_events, d_rev, d_any);
                    }
                    // assists: a campaign assists sessions whose start lies in
                    // [click.ts, click.ts + 7d] for some click of that campaign
                    if !pcl.is_empty() {
                        byc.clear();
                        byc.extend(pcl.iter().map(|c| (c.camp, c.ts as i64 + cbase)));
                        byc.sort_unstable();
                        let mut q = 0;
                        while q < byc.len() {
                            let c = byc[q].0;
                            let mut r = q;
                            let mut ilo = byc[q].1;
                            let mut ihi = ilo + WEEK;
                            let mut last_counted = 0usize;
                            let mut handle = |lo: i64, hi: i64, last_counted: &mut usize| {
                                let a = starts.partition_point(|&s| s < lo).max(*last_counted);
                                let b = starts.partition_point(|&s| s <= hi);
                                for s in a..b {
                                    camp_acc[c as usize * ndays + sess_days[s]][3] += 1;
                                }
                                if b > *last_counted {
                                    *last_counted = b;
                                }
                            };
                            r += 1;
                            while r < byc.len() && byc[r].0 == c {
                                let tt = byc[r].1;
                                if tt <= ihi {
                                    ihi = ihi.max(tt + WEEK);
                                } else {
                                    handle(ilo, ihi, &mut last_counted);
                                    ilo = tt;
                                    ihi = tt + WEEK;
                                }
                                r += 1;
                            }
                            handle(ilo, ihi, &mut last_counted);
                            q = r;
                        }
                    }
                    i = j;
                    ci = cj;
                }
            }
            bump::select(0);
            if !rows.is_empty() {
                // write this task's file now, so encoding overlaps other tasks; the
                // writer frees and reallocates buffers, so it uses the system allocator
                drop(acc_guard);
                bump::local_off();
                pq::write_user_daily(
                    &ud.join(format!("part-{t:05}.parquet")),
                    rows.len(),
                    |r| unpack(rows[r].0),
                    |r| rows[r].1,
                    |r| rows[r].2 as i64,
                    |r| rows[r].3 as i64,
                    |r| rows[r].4 as i64,
                    |r| if rows[r].5 < 0 { None } else { Some(&cat_ref[rows[r].5 as usize][..]) },
                )
                .unwrap();
                bump::local_on();
            }
            Part { user_rows: rows }
        })
        .collect();
    log!("sessionized {:?}", t0.elapsed());
    if parts.is_empty() {
        parts.push(Part { user_rows: vec![] });
    }

    // ---------------- merge campaign accumulators
    let mut camp_tot = vec![[0u64; 4]; ncamp * ndays];
    for acc in camp_accs.iter() {
        let acc = acc.lock().unwrap();
        for (i, a) in acc.iter().enumerate() {
            if a[0] | a[3] != 0 {
                for k in 0..4 {
                    camp_tot[i][k] += a[k];
                }
            }
        }
    }

    // ---------------- write outputs (the writer frees and reallocates buffers, so use the system allocator)
    bump::stop();
    if parts.iter().all(|p| p.user_rows.is_empty()) {
        pq::write_user_daily(&ud.join("part-00000.parquet"), 0, |_| &[][..], |_| 0, |_| 0, |_| 0, |_| 0, |_| None).unwrap();
    }
    let mut crows: Vec<(usize, usize)> = vec![];
    for c in 0..ncamp {
        for d in 0..ndays {
            let a = camp_tot[c * ndays + d];
            if a[0] > 0 || a[3] > 0 {
                crows.push((c, d));
            }
        }
    }
    pq::write_campaign_daily(
        &cd.join("part-00000.parquet"),
        crows.len(),
        |r| &camp_names[crows[r].0][..],
        |r| &camp_chan[crows[r].0][..],
        |r| (day0 + crows[r].1 as i64) as i32,
        |r| camp_tot[crows[r].0 * ndays + crows[r].1][0] as i64,
        |r| camp_tot[crows[r].0 * ndays + crows[r].1][1] as i64,
        |r| camp_tot[crows[r].0 * ndays + crows[r].1][2] as i64,
        |r| camp_tot[crows[r].0 * ndays + crows[r].1][3] as i64,
    )
    .unwrap();
    log!("done {:?}", t0.elapsed());
    // Drop the input page mappings from all workers: exit would otherwise
    // walk every page table entry of 1.9 GB of mapped files on one thread.
    #[cfg(unix)]
    {
        let maps: Vec<(usize, usize)> = ev_maps
            .iter()
            .chain(cl_maps.iter())
            .chain(ln_maps.iter())
            .flatten()
            .map(|m| (m.as_ptr() as usize, m.len()))
            .collect();
        maps.par_iter().for_each(|&(p, n)| unsafe {
            libc::madvise(p as *mut libc::c_void, n, libc::MADV_DONTNEED);
        });
        log!("released inputs {:?}", t0.elapsed());
        // Same for our own memory: exit would free gigabytes of huge pages on
        // one thread. Everything is written by now.
        if std::env::var_os("SS_KEEPMEM").is_none() {
            let pieces = bump::used_pieces(64 << 20);
            pieces.par_iter().for_each(|&(p, n)| unsafe {
                libc::madvise(p as *mut libc::c_void, n, libc::MADV_DONTNEED);
            });
            log!("released memory {:?}", t0.elapsed());
        }
    }
    // skip destructors of large structures
    stamp("end");
    std::process::exit(0);
}

/// Test data folders: the dev set and the kit fixtures, overridable for CI.
#[cfg(test)]
pub fn test_dir(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check_dir(dir: &Path) -> usize {
        let mut n = 0;
        let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                n += check_dir(&p);
            } else if p.extension().map(|x| x == "csv").unwrap_or(false) {
                let b = std::fs::read(&p).unwrap();
                for line in b.split(|&c| c == b'\n') {
                    assert_eq!(fields::<7>(line), fields_fast::<7>(line), "{:?}", String::from_utf8_lossy(line));
                    assert_eq!(fields::<4>(line), fields_fast::<4>(line));
                    assert_eq!(fields::<2>(line), fields_fast::<2>(line));
                    n += 1;
                }
            }
        }
        n
    }
    #[test]
    fn fast_splitter_matches_reference() {
        let mut n = check_dir(&test_dir("SS_TEST_FIXTURES", "../kit/starter-duckdb/starter-duckdb/fixtures"));
        n += check_dir(&test_dir("SS_TEST_DEV", "../data/dev"));
        for odd in [&b""[..], b",", b",,", b"\"", b"\"\"", b"\"a\"", b"a\"b", b"\"a", b"a\"", b"\"\"\"", b"x,\"y\",z,w", b"\"a\",\"b\"\r", b"a,b,c,d,e,f,g,h"] {
            assert_eq!(fields::<2>(odd), fields_fast::<2>(odd));
            assert_eq!(fields::<4>(odd), fields_fast::<4>(odd));
            assert_eq!(fields::<7>(odd), fields_fast::<7>(odd));
        }
        assert!(n > 1_000_000, "checked {n} lines");
        let dev = test_dir("SS_TEST_DEV", "../data/dev");
        for d in ["events", "clicks", "links"] {
            for e in std::fs::read_dir(dev.join(d)).unwrap().flatten() {
                let b = std::fs::read(e.path()).unwrap();
                let mut want7 = vec![]; let mut want4 = vec![]; let mut want2 = vec![];
                for_lines(&b, |l| { if let Some(x) = fields_fast::<7>(l) { want7.push(x) } if let Some(x) = fields_fast::<4>(l) { want4.push(x) } if let Some(x) = fields_fast::<2>(l) { want2.push(x) } });
                let mut got7 = vec![]; let mut got4 = vec![]; let mut got2 = vec![];
                for_records::<7>(&b, |x| got7.push(x));
                for_records::<4>(&b, |x| got4.push(x));
                for_records::<2>(&b, |x| got2.push(x));
                assert_eq!(want7, got7); assert_eq!(want4, got4); assert_eq!(want2, got2);
            }
        }
        for odd in [&b"a,b\n\nc,d\n"[..], b"\n\n", b"a,b", b"a,b\n", b"\"a\",\"b\"\n\"x\"y,z\n", b"a,b,c\nd,e\n"] {
            let mut want = vec![]; for_lines(odd, |l| if let Some(x) = fields_fast::<2>(l) { want.push(x) });
            let mut got = vec![]; for_records::<2>(odd, |x| got.push(x));
            assert_eq!(want, got);
        }
    }
}
