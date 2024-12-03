FROM debian

# "stable", "beta" or "nightly"
ARG RUST_TOOLCHAIN=stable

RUN apt-get update -y -qq && \
    apt-get install -y -qq --no-install-recommends curl python3 python3-venv clang make pkg-config nettle-dev libssl-dev ca-certificates pip codespell > /dev/null && \
    apt-get clean

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain none

RUN rustup toolchain install $RUST_TOOLCHAIN

COPY . /build
WORKDIR /build

RUN scripts/check
