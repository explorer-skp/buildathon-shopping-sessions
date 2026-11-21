"""Slow, literal reference for rules.md, used only to cross-check the Rust
pipeline on datasets other than the public dev set. Writes CSVs in the
fixtures' format (day as YYYY-MM-DD, empty top_category for null).

Usage: python reference.py DATA_DIR OUT_DIR
"""

import bisect
import calendar
import json
import os
import sys
from collections import defaultdict

DAY = 86_400_000
WEEK = 7 * DAY
DIG = set(b"0123456789")


def read_lines(path):
    data = open(path, "rb").read()
    parts = data.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts[1:]  # header


def parse(line, n):
    if line == b"":
        return None
    fs = line.split(b",")
    if len(fs) != n:
        return None
    out = []
    for f in fs:
        if b'"' in f:
            if len(f) >= 2 and f[0:1] == b'"' and f[-1:] == b'"' and b'"' not in f[1:-1]:
                f = f[1:-1]
            else:
                return None
        out.append(f)
    return out


def digits(b):
    return len(b) > 0 and all(c in DIG for c in b)


def ts_ms(b):
    if digits(b):
        return int(b)
    s = b
    if len(s) not in (20, 25):
        return None
    if not (s[4:5] == b"-" and s[7:8] == b"-" and s[10:11] == b"T" and s[13:14] == b":" and s[16:17] == b":"):
        return None
    for a, z in ((0, 4), (5, 7), (8, 10), (11, 13), (14, 16), (17, 19)):
        if not digits(s[a:z]):
            return None
    y, mo, d = int(s[0:4]), int(s[5:7]), int(s[8:10])
    h, mi, se = int(s[11:13]), int(s[14:16]), int(s[17:19])
    if not (1 <= mo <= 12) or h > 23 or mi > 59 or se > 59:
        return None
    if not (1 <= d <= calendar.monthrange(y, mo)[1]) if y >= 1 else True:
        return None
    if y < 1:
        return None
    base = calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) * 1000
    if len(s) == 20:
        return base if s[19:20] == b"Z" else None
    sign = s[19:20]
    if sign not in (b"+", b"-") or s[22:23] != b":" or not digits(s[20:22]) or not digits(s[23:25]):
        return None
    oh, om = int(s[20:22]), int(s[23:25])
    if oh > 23 or om > 59:
        return None
    off = (oh * 3600 + om * 60) * 1000
    return base - off if sign == b"+" else base + off


def csvs(d):
    if not os.path.isdir(d):
        return []
    return sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith(".csv"))


def main():
    data, out = sys.argv[1], sys.argv[2]
    man = json.load(open(os.path.join(data, "manifest.json")))
    ws = ts_ms(man["window_start"].encode())
    we = ts_ms(man["window_end"].encode())

    prod = {}
    for l in read_lines(os.path.join(data, "products.csv")):
        r = parse(l, 2)
        if r:
            prod.setdefault(r[0], r[1])
    camps = {}
    for l in read_lines(os.path.join(data, "campaigns.csv")):
        r = parse(l, 2)
        if r:
            camps.setdefault(r[0], r[1])

    # links
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for f in csvs(os.path.join(data, "links")):
        for l in read_lines(f):
            r = parse(l, 2)
            if not r or r[0] == b"" or r[1] == b"":
                continue
            a, b = find(r[0]), find(r[1])
            if a != b:
                if a < b:
                    parent[b] = a
                else:
                    parent[a] = b

    def person(u):
        return find(u) if u in parent else u

    # events
    best = {}
    for f in csvs(os.path.join(data, "events")):
        for l in read_lines(f):
            r = parse(l, 7)
            if not r or r[0] == b"":
                continue
            ing = ts_ms(r[3])
            cur = best.get(r[0])
            if cur is None or ing < cur[0]:
                best[r[0]] = (ing, r)
    evs = defaultdict(list)
    for eid, (ing, r) in best.items():
        _, uid, ts, _, typ, pid, price = r
        if uid == b"" or pid == b"":
            continue
        t = ts_ms(ts)
        if t is None or not (ws <= t < we):
            continue
        if typ not in (b"view", b"cart", b"purchase"):
            continue
        p = 0
        if typ == b"purchase":
            if not digits(price):
                continue
            p = int(price)
            if not (1 <= p <= 10_000_000):
                continue
        if ing - t > DAY:
            continue
        cat = prod.get(pid, b"unknown") if typ == b"purchase" else None
        evs[person(uid)].append((t, p, cat))

    # clicks
    clicks = defaultdict(list)
    seen = set()
    for f in csvs(os.path.join(data, "clicks")):
        for l in read_lines(f):
            r = parse(l, 4)
            if not r or r[0] == b"":
                continue
            if r[0] in seen:
                continue
            seen.add(r[0])
            cid, uid, cmp, ts = r
            if uid == b"":
                continue
            t = ts_ms(ts)
            if t is None or not (ws - WEEK <= t < we):
                continue
            if cmp not in camps:
                continue
            clicks[person(uid)].append((t, cid, cmp))
    for v in clicks.values():
        v.sort()

    user_rows = {}
    camp_rows = defaultdict(lambda: [0, 0, 0, 0])
    for per, lst in evs.items():
        lst.sort(key=lambda x: x[0])
        sessions = []
        cur = None
        for t, p, cat in lst:
            if cur is None or t - cur["last"] > 1_800_000:
                cur = {"start": t, "last": t, "events": 0, "rev": 0, "cats": defaultdict(int)}
                sessions.append(cur)
            cur["last"] = t
            cur["events"] += 1
            if p:
                cur["rev"] += p
                cur["cats"][cat] += p
        cl = clicks.get(per, [])
        cts = [c[0] for c in cl]
        for s in sessions:
            day = s["start"] // DAY
            key = (per, day)
            row = user_rows.setdefault(key, [0, 0, 0, defaultdict(int)])
            row[0] += 1
            row[1] += s["events"]
            row[2] += s["rev"]
            for c, v in s["cats"].items():
                row[3][c] += v
            lo = bisect.bisect_left(cts, s["start"] - WEEK)
            hi = bisect.bisect_right(cts, s["start"])
            win = cl[lo:hi]
            if win:
                tmax = max(c[0] for c in win)
                credited = min(c[1] for c in win if c[0] == tmax)
                cmp = next(c[2] for c in win if c[0] == tmax and c[1] == credited)
            else:
                cmp = b"organic"
            r = camp_rows[(cmp, day)]
            r[0] += 1
            r[1] += 1 if s["rev"] > 0 else 0
            r[2] += s["rev"]
            for c in {c[2] for c in win}:
                camp_rows[(c, day)][3] += 1

    os.makedirs(out, exist_ok=True)
    import datetime

    def dstr(d):
        return (datetime.date(1970, 1, 1) + datetime.timedelta(days=d)).isoformat()

    with open(os.path.join(out, "user_daily.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("user_id,day,sessions,events,revenue_cents,top_category\n")
        for (per, day), (s, e, rev, cats) in user_rows.items():
            top = ""
            if cats:
                top = min(cats.items(), key=lambda kv: (-kv[1], kv[0]))[0].decode()
            f.write(f"{per.decode()},{dstr(day)},{s},{e},{rev},{top}\n")
    with open(os.path.join(out, "campaign_daily.csv"), "w", encoding="utf-8", newline="") as f:
        f.write("campaign_id,channel,day,sessions,purchasing_sessions,revenue_cents,assisted_sessions\n")
        for (c, day), (s, ps, rev, a) in camp_rows.items():
            ch = b"organic" if c == b"organic" else camps[c]
            f.write(f"{c.decode()},{ch.decode()},{dstr(day)},{s},{ps},{rev},{a}\n")


if __name__ == "__main__":
    main()
