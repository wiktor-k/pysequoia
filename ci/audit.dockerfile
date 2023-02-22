FROM rust

RUN cargo install cargo-audit

COPY . /build
WORKDIR /build

RUN cargo audit --ignore \
    # chrono doesn't use affected version
    # to be removed when chrono 0.5 is released
    # see: https://github.com/chronotope/chrono/commit/43579a5304f9433ce42614e200b554ea8e0361cc
    RUSTSEC-2020-0071
