//! Minimal Parquet writers for the two output tables (uncompressed, plain
//! encoding, one row group per file).

use parquet::basic::Compression;
use parquet::data_type::{ByteArray, ByteArrayType, Int32Type, Int64Type};
use parquet::file::properties::{WriterProperties, WriterVersion};
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::sync::Arc;

type R = Result<(), Box<dyn std::error::Error>>;

fn props() -> Arc<WriterProperties> {
    Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::UNCOMPRESSED)
            .set_writer_version(WriterVersion::PARQUET_1_0)
            .set_dictionary_enabled(false)
            .set_statistics_enabled(parquet::file::properties::EnabledStatistics::None)
            .set_data_page_row_count_limit(1 << 20)
            .build(),
    )
}

fn bytes_col<'a>(n: usize, f: impl Fn(usize) -> &'a [u8]) -> Vec<ByteArray> {
    (0..n).map(|i| ByteArray::from(f(i).to_vec())).collect()
}

#[allow(clippy::too_many_arguments)]
pub fn write_user_daily<'a>(
    path: &Path,
    n: usize,
    user: impl Fn(usize) -> &'a [u8],
    day: impl Fn(usize) -> i32,
    sessions: impl Fn(usize) -> i64,
    events: impl Fn(usize) -> i64,
    revenue: impl Fn(usize) -> i64,
    top: impl Fn(usize) -> Option<&'a [u8]>,
) -> R {
    let schema = Arc::new(parse_message_type(
        "message user_daily {
            required binary user_id (STRING);
            required int32 day (DATE);
            required int64 sessions;
            required int64 events;
            required int64 revenue_cents;
            optional binary top_category (STRING);
        }",
    )?);
    let file = BufWriter::with_capacity(1 << 22, File::create(path)?);
    let mut w = SerializedFileWriter::new(file, schema, props())?;
    let mut rg = w.next_row_group()?;
    {
        let mut c = rg.next_column()?.unwrap();
        c.typed::<ByteArrayType>().write_batch(&bytes_col(n, &user), None, None)?;
        c.close()?;
    }
    {
        let mut c = rg.next_column()?.unwrap();
        let v: Vec<i32> = (0..n).map(&day).collect();
        c.typed::<Int32Type>().write_batch(&v, None, None)?;
        c.close()?;
    }
    for f in [&sessions as &dyn Fn(usize) -> i64, &events, &revenue] {
        let mut c = rg.next_column()?.unwrap();
        let v: Vec<i64> = (0..n).map(f).collect();
        c.typed::<Int64Type>().write_batch(&v, None, None)?;
        c.close()?;
    }
    {
        let mut c = rg.next_column()?.unwrap();
        let mut vals = Vec::new();
        let mut defs = Vec::with_capacity(n);
        for i in 0..n {
            match top(i) {
                Some(b) => {
                    vals.push(ByteArray::from(b.to_vec()));
                    defs.push(1i16);
                }
                None => defs.push(0),
            }
        }
        c.typed::<ByteArrayType>().write_batch(&vals, Some(&defs), None)?;
        c.close()?;
    }
    rg.close()?;
    w.close()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn write_campaign_daily<'a>(
    path: &Path,
    n: usize,
    camp: impl Fn(usize) -> &'a [u8],
    chan: impl Fn(usize) -> &'a [u8],
    day: impl Fn(usize) -> i32,
    sessions: impl Fn(usize) -> i64,
    purch: impl Fn(usize) -> i64,
    revenue: impl Fn(usize) -> i64,
    assisted: impl Fn(usize) -> i64,
) -> R {
    let schema = Arc::new(parse_message_type(
        "message campaign_daily {
            required binary campaign_id (STRING);
            required binary channel (STRING);
            required int32 day (DATE);
            required int64 sessions;
            required int64 purchasing_sessions;
            required int64 revenue_cents;
            required int64 assisted_sessions;
        }",
    )?);
    let file = BufWriter::new(File::create(path)?);
    let mut w = SerializedFileWriter::new(file, schema, props())?;
    let mut rg = w.next_row_group()?;
    for f in [&camp as &dyn Fn(usize) -> &'a [u8], &chan] {
        let mut c = rg.next_column()?.unwrap();
        c.typed::<ByteArrayType>().write_batch(&bytes_col(n, f), None, None)?;
        c.close()?;
    }
    {
        let mut c = rg.next_column()?.unwrap();
        let v: Vec<i32> = (0..n).map(&day).collect();
        c.typed::<Int32Type>().write_batch(&v, None, None)?;
        c.close()?;
    }
    for f in [&sessions as &dyn Fn(usize) -> i64, &purch, &revenue, &assisted] {
        let mut c = rg.next_column()?.unwrap();
        let v: Vec<i64> = (0..n).map(f).collect();
        c.typed::<Int64Type>().write_batch(&v, None, None)?;
        c.close()?;
    }
    rg.close()?;
    w.close()?;
    Ok(())
}
