FROM rust

RUN apt update -y -qq && \
    apt install -y -qq --no-install-recommends python3 python3-venv clang make pkg-config nettle-dev libssl-dev ca-certificates pip patchelf && \
    apt clean
RUN cargo install tangler

COPY . /build
WORKDIR /build

RUN tangler bash < README.md > README.sh
RUN tangler python < README.md > README.py

SHELL ["/bin/bash", "-c", "source README.sh && python3 README.py"]
# not sure why but "python3 README.py" needs to be above and below to be executed
RUN python3 README.py
