FROM rust

RUN cargo install --locked cargo-deny

COPY . /build
WORKDIR /build

RUN cargo deny check
