FROM rust

RUN apt update -y -qq && \
    apt install -y -qq --no-install-recommends python3 python3-venv clang make pkg-config nettle-dev libssl-dev ca-certificates pip && \
    apt clean
RUN rustup component add rustfmt clippy

COPY . /build
WORKDIR /build

# Run fastest tests first before running longer checks
RUN cargo fmt -- --check
RUN cargo clippy --all
RUN cargo test --all --verbose
