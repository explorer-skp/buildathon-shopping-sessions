# Shopping Sessions

A single Rust binary for the Databricks Shopping Sessions track of the Builders Buildathon. It reads the click-stream CSVs in `/data`, applies every rule in the track's `rules.md`, and writes the `user_daily` and `campaign_daily` Parquet tables to `/output`.

## How it works

1. Every CSV file is memory-mapped and split into lines in parallel. A hand-written field splitter follows the track's CSV dialect exactly: quotes only around a whole field, `\r` kept as data, empty fields as null.
2. Timestamps in all three forms are parsed by hand into epoch milliseconds, with full calendar and offset checks.
3. Links are joined with a union-find, and each person is named by the byte-wise smallest of their IDs.
4. Events are deduplicated on `event_id` (smallest `ingest_ts` wins) before validation, then late events are dropped.
5. Each person's events are sorted by time and split into sessions at gaps over 30 minutes. Sessions are credited to the person's latest qualifying click within 7 days, and every campaign with a qualifying click assists.
6. Both tables are aggregated in memory and written as Parquet with `day` as a `DATE`.

## Build and run

```sh
docker build -t shopping-sessions .
docker run --rm -v "$PWD/data:/data:ro" -v "$PWD/out:/output" shopping-sessions
```

Without Docker: `cargo build --release`, then run `target/release/sessions` with `DATA_DIR` and `OUTPUT_DIR` set.

## Open-source libraries

- `memchr` for fast byte search
- `memmap2` for memory-mapped input files
- `rayon` for parallel parsing and aggregation
- `xxhash-rust` (xxh3) for hashing IDs
- `parquet` (Apache Arrow Rust) for writing the output tables

## License

MIT. See `LICENSE`.
