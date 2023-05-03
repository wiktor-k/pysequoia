FROM registry.gitlab.com/openpgp-card/virtual-cards/opcard-rs-tools

RUN apt-get update -y -qq && \
    apt-get install -y -qq --no-install-recommends python-is-python3 python3-venv clang make pkg-config nettle-dev libssl-dev ca-certificates pip patchelf pcscd libpcsclite-dev && \
    apt-get clean
RUN cargo install --locked tangler openpgp-card-tools

COPY . /build
WORKDIR /build

RUN tangler bash < README.md > README.sh
RUN tangler python < README.md > README.py

SHELL ["/bin/bash", "-c", "source README.sh && python README.py"]
# not sure why but "python README.py" needs to be above and below to be executed
RUN python README.py
