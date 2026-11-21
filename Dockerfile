# Shopping Sessions: a single Rust binary that reads /data and writes /output.
FROM rust:1.91-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# AVX2-level code: every Haswell-or-newer Xeon, including the scorers' Cascade Lake.
ENV RUSTFLAGS="-C target-cpu=x86-64-v3"
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/target/release/sessions /usr/local/bin/sessions
ENV SS_QUIET=1
# Back malloc arenas with transparent huge pages where the kernel allows it (THP in madvise mode).
# On x86 this cut the 20M-event run from 3.91 s to 3.77 s in the bench workflow.
ENV GLIBC_TUNABLES=glibc.malloc.hugetlb=1
# measurement build: the pipeline runs twice, to separate compute time from fixed overhead
ENV SS_TWICE=1
CMD ["/usr/local/bin/sessions"]
