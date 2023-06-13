#!/usr/bin/env bash

if [ -f /usr/bin/yum ]; then
    yum install -y openssl-devel pcsc-lite-devel centos-release-scl llvm-toolset-7

    source /opt/rh/llvm-toolset-7/enable

    PREFIX=/
    GMP_VERSION=6.2.1
    NETTLE_VERSION=3.9.1

 cd /tmp && \
    curl -O https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.bz2 && \
    tar xvf gmp-${GMP_VERSION}.tar.bz2 && \
    cd gmp-${GMP_VERSION} && \
    ./configure --prefix=$PREFIX && \
    make && make install

cd /tmp &&
    curl -O https://ftp.gnu.org/gnu/nettle/nettle-${NETTLE_VERSION}.tar.gz && \
    tar xvf nettle-${NETTLE_VERSION}.tar.gz && \
    cd nettle-${NETTLE_VERSION} && \
    ./configure --prefix=$PREFIX \
      --with-lib-path=$PREFIX/lib \
      --with-include-path=$PREFIX/include \
      --disable-openssl && \
    make && make install
else
    apt-get update
    apt-get install -yqq cargo clang git nettle-dev pkg-config libssl-dev openssl libpcsclite-dev llvm gcc-multilib libgmp-dev libgmp3-dev
fi
