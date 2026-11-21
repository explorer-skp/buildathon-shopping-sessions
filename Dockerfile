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
CMD ["/usr/local/bin/sessions"]
