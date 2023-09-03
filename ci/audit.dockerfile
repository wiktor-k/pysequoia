FROM rust

RUN cargo install cargo-audit

COPY . /build
WORKDIR /build

RUN cargo audit
