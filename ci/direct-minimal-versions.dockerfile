FROM rustlang/rust:nightly

RUN apt-get update -y -qq && \
    apt-get install -y -qq --no-install-recommends clang make pkg-config nettle-dev libssl-dev pcscd libpcsclite-dev

COPY . /build
WORKDIR /build

RUN cargo +nightly check -Zdirect-minimal-versions
