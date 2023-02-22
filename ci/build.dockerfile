FROM rust

RUN apt-get update -y -qq && \
    apt-get install -y -qq --no-install-recommends python3 python3-venv clang make pkg-config nettle-dev libssl-dev ca-certificates pip pcscd libpcsclite-dev codespell && \
    apt-get clean
RUN rustup component add rustfmt clippy

COPY . /build
WORKDIR /build

RUN ci/quick-checks.sh
