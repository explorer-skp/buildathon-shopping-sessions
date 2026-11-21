//! Shopping Sessions pipeline: one pass over memory-mapped CSV files, all
//! rules from rules.md implemented by hand so the CSV dialect is exact.

use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;
use xxhash_rust::xxh3::{xxh3_128, xxh3_64};

mod pq;

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
    ($($t:tt)*) => { if std::env::var_os("SS_QUIET").is_none() { eprintln!($($t)*); } }
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

/// Hint the CPU to pull a cache line in ahead of use.
#[inline(always)]
fn prefetch<T>(p: *const T) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_mm_prefetch(p as *const i8, std::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        std::arch::asm!("prfm pldl1keep, [{0}]", in(reg) p, options(nostack, readonly, preserves_flags));
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
    // F3: digits only
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

/// Open-addressing table from an ID hash to (person key, person name ref).
/// Keys are xxh3 hashes, so the low bits index directly. Key 0 marks empty.
struct LinkTable {
    n: usize,
    mask: usize,
    slots: Vec<(u64, u64, u64)>,
}

impl LinkTable {
    fn new(n: usize) -> Self {
        let cap = ((n * 8 / 5).max(16)).next_power_of_two();
        LinkTable { n: 0, mask: cap - 1, slots: vec![(0, 0, 0); cap] }
    }
    #[inline]
    fn fix(k: u64) -> u64 {
        if k == 0 { 0x9e37_79b9_7f4a_7c15 } else { k }
    }
    fn insert(&mut self, k: u64, pk: u64, nref: u64) {
        let k = Self::fix(k);
        let mut i = (k as usize) & self.mask;
        loop {
            let s = &mut self.slots[i];
            if s.0 == 0 || s.0 == k {
                *s = (k, pk, nref);
                return;
            }
            i = (i + 1) & self.mask;
        }
    }
    #[inline(always)]
    fn prefetch(&self, k: u64) {
        let i = (Self::fix(k) as usize) & self.mask;
        prefetch(self.slots.as_ptr().wrapping_add(i));
    }
    #[inline]
    fn get(&self, k: u64) -> Option<(u64, u64)> {
        let k = Self::fix(k);
        let mut i = (k as usize) & self.mask;
        loop {
            let s = &self.slots[i];
            if s.0 == k {
                return Some((s.1, s.2));
            }
            if s.0 == 0 {
                return None;
            }
            i = (i + 1) & self.mask;
        }
    }
}

// ------------------------------------------------------------------ records

/// One parsed (non-malformed) event copy, before dedup.
#[derive(Clone, Copy, Default)]
struct Ev {
    eid: [u64; 2],
    ingest: i64,
    uh: u64,   // user_id hash (meaningful when ok)
    uref: u64, // user_id bytes (meaningful when ok)
    ts: u32,   // ms since window start (meaningful when ok)
    price: u32,
    cat: u16,
    ok: bool, // passes validation (before the late rule)
}

/// A surviving event, routed to its person's partition.
#[derive(Clone, Copy)]
struct EvP {
    pk: u64,
    nref: u64,
    ts: u32,
    price: u32,
    cat: u16,
}

/// A valid click, routed to its person's partition.
#[derive(Clone, Copy)]
struct ClP {
    pk: u64,
    cid: u64,
    ts: u32, // ms since window start - 7 days
    camp: u32,
}

const NB: usize = 512; // event dedup buckets (by event_id hash)
const PB: u32 = 10; // person partitions = 1 << PB (by person key)
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

// ------------------------------------------------------------------ phases

/// Joins every link line into people and returns the table from an ID hash
/// to (person key, person name). The person key is the hash of the person's
/// byte-wise smallest ID, and the name points at that ID's bytes.
fn build_links(maps: &[Option<Mmap>], chunks: &[Chunk]) -> LinkTable {
    let ln_parsed: Vec<Vec<(u64, u64, u64, u64)>> = chunks
        .par_iter()
        .map(|c| {
            let b: &[u8] = maps[c.file].as_ref().unwrap();
            let buf = &b[c.start..c.end];
            let mut v = Vec::new();
            for_lines(buf, |l| {
                let Some([a, bb]) = fields_fast::<2>(l) else { return };
                if a.is_empty() || bb.is_empty() {
                    return;
                }
                v.push((xxh3_64(a), xxh3_64(bb), pack(a), pack(bb)));
            });
            v
        })
        .collect();
    let mut ids: Vec<(u64, u64)> = ln_parsed
        .par_iter()
        .flat_map_iter(|v| v.iter().flat_map(|&(ha, hb, ra, rb)| [(ha, ra), (hb, rb)]))
        .collect();
    ids.par_sort_unstable_by_key(|x| x.0);
    ids.dedup_by_key(|x| x.0);
    let n_ids = ids.len();
    let mut dense = LinkTable::new(n_ids);
    for (i, x) in ids.iter().enumerate() {
        dense.insert(x.0, i as u64, 0);
    }
    let dense_of = |h: u64| -> u32 { dense.get(h).unwrap().0 as u32 };
    let mut parent: Vec<u32> = (0..n_ids as u32).collect();
    fn find(p: &mut [u32], mut x: u32) -> u32 {
        while p[x as usize] != x {
            let g = p[p[x as usize] as usize];
            p[x as usize] = g;
            x = g;
        }
        x
    }
    for v in &ln_parsed {
        for &(a, b, _, _) in v {
            let ra = find(&mut parent, dense_of(a));
            let rb = find(&mut parent, dense_of(b));
            if ra != rb {
                // the root keeps the byte-wise smaller name, so roots name people
                if unpack(ids[ra as usize].1) <= unpack(ids[rb as usize].1) {
                    parent[rb as usize] = ra;
                } else {
                    parent[ra as usize] = rb;
                }
            }
        }
    }
    drop(dense);
    let mut link = LinkTable::new(n_ids);
    for i in 0..n_ids as u32 {
        let r = find(&mut parent, i) as usize;
        link.insert(ids[i as usize].0, ids[r].0, ids[r].1);
    }
    link.n = n_ids;
    link
}

/// Parses every event file into dedup buckets keyed by the event_id hash.
/// Persons are resolved later, after dedup, once the link table exists.
fn parse_events(
    maps: &[Option<Mmap>],
    chunks: &[Chunk],
    ws: i64,
    we: i64,
    prod: &StrMap<u16>,
    unknown_cat: u16,
) -> Vec<Vec<Vec<Ev>>> {
    chunks
        .par_iter()
        .map(|c| {
            let b: &[u8] = maps[c.file].as_ref().unwrap();
            let buf = &b[c.start..c.end];
            let mut buckets: Vec<Vec<Ev>> = (0..NB).map(|_| Vec::with_capacity(buf.len() / 70 / NB + 8)).collect();
            for_lines(buf, |l| {
                let Some([eid, uid, ts, ing, typ, pid, price]) = fields_fast::<7>(l) else { return };
                if eid.is_empty() {
                    return;
                }
                let h = xxh3_128(eid);
                let ingest = parse_ts(ing).unwrap_or(i64::MAX);
                let mut ok = !uid.is_empty() && !pid.is_empty();
                let tsv = match parse_ts(ts) {
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
                let (uh, uref) = if ok { (xxh3_64(uid), pack(uid)) } else { (0, 0) };
                let e = Ev { eid: [h as u64, (h >> 64) as u64], ingest, uh, uref, ts: tsv, price: pr, cat, ok };
                buckets[(h >> 64) as usize % NB].push(e);
            });
            buckets
        })
        .collect()
}

/// Parses every click file into one vector per chunk. `pk` holds the user
/// hash until the link table resolves it to the person.
fn parse_clicks(maps: &[Option<Mmap>], chunks: &[Chunk], cbase: i64, we: i64, camp: &StrMap<u32>) -> Vec<Vec<ClP>> {
    chunks
        .par_iter()
        .map(|c| {
            let b: &[u8] = maps[c.file].as_ref().unwrap();
            let buf = &b[c.start..c.end];
            let mut v = Vec::with_capacity(buf.len() / 45 + 16);
            for_lines(buf, |l| {
                let Some([cid, uid, cmp, ts]) = fields_fast::<4>(l) else { return };
                if cid.is_empty() || uid.is_empty() {
                    return;
                }
                let Some(t) = parse_ts(ts) else { return };
                if t < cbase || t >= we {
                    return;
                }
                let Some(ci) = camp.get(cmp) else { return };
                v.push(ClP { pk: xxh3_64(uid), cid: pack(cid), ts: (t - cbase) as u32, camp: ci });
            });
            v
        })
        .collect()
}

fn main() {
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
    log!("tables {:?}", t0.elapsed());

    let target = 4 << 20;
    let ev_chunks = chunks(&ev_maps, target);
    let cl_chunks = chunks(&cl_maps, target);
    let ln_chunks = chunks(&ln_maps, 1 << 20);

    // ---------------- links on one worker, overlapped with parsing events and clicks
    let (link, (parsed, cl_raw)) = rayon::join(
        || build_links(&ln_maps, &ln_chunks),
        || {
            let p = parse_events(&ev_maps, &ev_chunks, ws, we, &prod, unknown_cat);
            log!("parsed events {:?}", t0.elapsed());
            let c = parse_clicks(&cl_maps, &cl_chunks, cbase, we, &camp);
            log!("parsed clicks {:?}", t0.elapsed());
            (p, c)
        },
    );
    let link = &link;
    log!("linked {} ids, all parsed {:?}", link.n, t0.elapsed());

    // ---------------- clicks: resolve persons, route to person partitions
    let cl_parts: Vec<Vec<Vec<ClP>>> = cl_raw
        .par_iter()
        .map(|v| {
            let per = v.len() / NP;
            let mut parts: Vec<Vec<ClP>> = (0..NP).map(|_| Vec::with_capacity(per + per / 4 + 4)).collect();
            for i in 0..v.len() {
                if i + 8 < v.len() {
                    link.prefetch(v[i + 8].pk);
                }
                let mut c = v[i];
                if let Some(x) = link.get(c.pk) {
                    c.pk = x.0;
                }
                parts[part_of(c.pk)].push(c);
            }
            parts
        })
        .collect();
    std::mem::forget(cl_raw);
    log!("routed clicks {:?}", t0.elapsed());

    // ---------------- dedup events per bucket, resolve persons, route to person partitions
    let groups = (ncpu * 8).clamp(1, NB);
    let per_g = NB.div_ceil(groups);
    let parsed_ref = &parsed;
    let dd: Vec<Vec<Vec<EvP>>> = (0..groups)
        .into_par_iter()
        .map(|g| {
            let lo_b = g * per_g;
            let hi_b = ((g + 1) * per_g).min(NB);
            let n_est: usize = (lo_b..hi_b).map(|bi| parsed_ref.iter().map(|p| p[bi].len()).sum::<usize>()).sum();
            let mut parts: Vec<Vec<EvP>> = (0..NP).map(|_| Vec::with_capacity(n_est / NP + n_est / NP / 4 + 4)).collect();
            // Open-addressing table of (low eid word, record) per bucket. The
            // record kept for an event_id is its copy with the smallest ingest_ts.
            let mut table: Vec<(u64, *const Ev)> = Vec::new();
            let mut kept: Vec<*const Ev> = Vec::new();
            for bi in lo_b..hi_b {
                let n: usize = parsed_ref.iter().map(|p| p[bi].len()).sum();
                if n == 0 {
                    continue;
                }
                let cap = (n * 2).next_power_of_two().max(16);
                let mask = cap - 1;
                table.clear();
                table.resize(cap, (0, std::ptr::null()));
                for p in parsed_ref.iter() {
                    for e in p[bi].iter() {
                        let mut s = (e.eid[0] as usize) & mask;
                        loop {
                            let (fp, cur) = table[s];
                            if cur.is_null() {
                                table[s] = (e.eid[0], e as *const Ev);
                                break;
                            }
                            if fp == e.eid[0] {
                                let c = unsafe { &*cur };
                                if c.eid[1] == e.eid[1] {
                                    if e.ingest < c.ingest {
                                        table[s].1 = e as *const Ev;
                                    }
                                    break;
                                }
                            }
                            s = (s + 1) & mask;
                        }
                    }
                }
                kept.clear();
                for &(_, ptr) in table.iter() {
                    if ptr.is_null() {
                        continue;
                    }
                    let e = unsafe { &*ptr };
                    if e.ok && e.ingest - (e.ts as i64 + ws) <= DAY {
                        kept.push(ptr);
                    }
                }
                for i in 0..kept.len() {
                    if i + 8 < kept.len() {
                        link.prefetch(unsafe { (*kept[i + 8]).uh });
                    }
                    let e = unsafe { &*kept[i] };
                    let (pk, nref) = link.get(e.uh).unwrap_or((e.uh, e.uref));
                    parts[part_of(pk)].push(EvP { pk, nref, ts: e.ts, price: e.price, cat: e.cat });
                }
            }
            parts
        })
        .collect();
    std::mem::forget(parsed);
    log!("deduped {:?}", t0.elapsed());

    // ---------------- sessionize, attribute, aggregate (parallel by person partitions)
    let ndays = ((we - ws + DAY - 1) / DAY + 1) as usize;
    let day0 = ws.div_euclid(DAY);
    let tasks = (ncpu * 8).clamp(1, NP);
    let per_t = NP.div_ceil(tasks);

    struct Part {
        user_rows: Vec<(u64, i32, u32, u32, u64, i32)>, // name, day, sessions, events, revenue, top cat (-1)
        camp: Vec<[u64; 4]>,                           // ncamp*ndays: sessions, purchasing, revenue, assisted
    }
    let dd_ref = &dd;
    let cl_ref = &cl_parts;
    let cat_rank = &cat_rank;
    let mut parts: Vec<Part> = (0..tasks)
        .into_par_iter()
        .map(|t| {
            let mut camp_acc = vec![[0u64; 4]; ncamp * ndays];
            let mut rows = Vec::new();
            let mut catrev = vec![0u64; ncat];
            let mut starts: Vec<i64> = Vec::new();
            let mut sess_days: Vec<usize> = Vec::new();
            let mut evs: Vec<EvP> = Vec::new();
            let mut cls: Vec<ClP> = Vec::new();
            let mut byc: Vec<(u32, i64)> = Vec::new();
            for p in t * per_t..((t + 1) * per_t).min(NP) {
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
                            let price = evs[m].price as u64;
                            if price > 0 {
                                rev += price;
                                purch = true;
                                catrev[evs[m].cat as usize] += price;
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
            Part { user_rows: rows, camp: camp_acc }
        })
        .collect();
    log!("sessionized {:?}", t0.elapsed());
    if parts.is_empty() {
        parts.push(Part { user_rows: vec![], camp: vec![[0u64; 4]; ncamp * ndays] });
    }

    // ---------------- merge campaign accumulators
    let mut camp_tot = vec![[0u64; 4]; ncamp * ndays];
    for p in &parts {
        for (i, a) in p.camp.iter().enumerate() {
            if a[0] | a[3] != 0 {
                for k in 0..4 {
                    camp_tot[i][k] += a[k];
                }
            }
        }
    }

    // ---------------- write outputs
    let ud = out.join("user_daily");
    let cd = out.join("campaign_daily");
    std::fs::create_dir_all(&ud).unwrap();
    std::fs::create_dir_all(&cd).unwrap();

    let cat_ref = &cat_names;
    let all_empty = parts.iter().all(|p| p.user_rows.is_empty());
    parts.par_iter().enumerate().for_each(|(pi, p)| {
        if p.user_rows.is_empty() && !(all_empty && pi == 0) {
            return;
        }
        let rows = &p.user_rows;
        pq::write_user_daily(
            &ud.join(format!("part-{pi:05}.parquet")),
            rows.len(),
            |r| unpack(rows[r].0),
            |r| rows[r].1,
            |r| rows[r].2 as i64,
            |r| rows[r].3 as i64,
            |r| rows[r].4 as i64,
            |r| if rows[r].5 < 0 { None } else { Some(&cat_ref[rows[r].5 as usize][..]) },
        )
        .unwrap();
    });
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
    // skip destructors of large structures
    std::process::exit(0);
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
        let mut n = check_dir(Path::new("../kit/starter-duckdb/starter-duckdb/fixtures"));
        n += check_dir(Path::new("../data/dev"));
        for odd in [&b""[..], b",", b",,", b"\"", b"\"\"", b"\"a\"", b"a\"b", b"\"a", b"a\"", b"\"\"\"", b"x,\"y\",z,w", b"\"a\",\"b\"\r", b"a,b,c,d,e,f,g,h"] {
            assert_eq!(fields::<2>(odd), fields_fast::<2>(odd));
            assert_eq!(fields::<4>(odd), fields_fast::<4>(odd));
            assert_eq!(fields::<7>(odd), fields_fast::<7>(odd));
        }
        assert!(n > 1_000_000, "checked {n} lines");
    }
}
