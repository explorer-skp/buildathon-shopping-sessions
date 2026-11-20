# Shopping Sessions: a single Rust binary that reads /data and writes /output.
FROM rust:1.91-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/target/release/sessions /usr/local/bin/sessions
ENV SS_QUIET=1
CMD ["/usr/local/bin/sessions"]
