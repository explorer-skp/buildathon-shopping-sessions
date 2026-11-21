import sys
import polars as pl
a, b = sys.argv[1], sys.argv[2]
ok = True
for t in ["user_daily", "campaign_daily"]:
    da = pl.read_parquet(f"{a}/{t}/*.parquet")
    db = pl.read_parquet(f"{b}/{t}/*.parquet")
    cols = sorted(da.columns)
    if sorted(db.columns) != cols:
        print(t, "COLUMNS DIFFER", da.columns, db.columns); ok = False; continue
    da = da.select(cols).with_columns([pl.col(c).cast(pl.Int64) for c in cols if da.schema[c].is_integer()])
    db = db.select(cols).with_columns([pl.col(c).cast(pl.Int64) for c in cols if db.schema[c].is_integer()])
    da = da.sort(cols, nulls_last=True); db = db.sort(cols, nulls_last=True)
    same = da.height == db.height and da.equals(db)
    print(t, "rows", da.height, db.height, "EQUAL" if same else "DIFFERENT")
    ok &= same
print("ALL EQUAL" if ok else "MISMATCH")
