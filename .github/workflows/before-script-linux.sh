#!/usr/bin/env bash

set -euxo pipefail

if [ -f /usr/bin/yum ]; then
    echo Manylinux2010 build

    #yum install -y centos-release-scl llvm-toolset-7 flex

    #source /opt/rh/llvm-toolset-7/enable

    PREFIX=/

    # Need to download from mirror because of: https://www.theregister.com/2023/06/28/microsofts_github_gmp_project/
    # See: https://ftp.gnu.org/gnu/gmp/
    GMP_VERSION=6.3.0

    # See: https://ftp.gnu.org/gnu/nettle/
    NETTLE_VERSION=3.9.1

    # See: https://pcsclite.apdu.fr/files/
    PCSCLITE_VERSION=2.0.1

    cd /tmp &&
    curl --fail -sSL -O https://pcsclite.apdu.fr/files/pcsc-lite-${PCSCLITE_VERSION}.tar.bz2 && \
    tar xf pcsc-lite-${PCSCLITE_VERSION}.tar.bz2 && \
    cd pcsc-lite-${PCSCLITE_VERSION} && \
    ./configure --prefix=$PREFIX \
      --disable-libsystemd \
      --disable-libudev \
      --disable-libusb \
      --disable-polkit \
      --enable-filter \
      --enable-ipcdir=/run/pcscd \
      --enable-usbdropdir=/usr/lib/pcsc/drivers && \
    make && make install

    cd /tmp && \
    curl --fail -sSL -O https://ftp.gnu.org/gnu/gmp/gmp-${GMP_VERSION}.tar.bz2 && \
    tar xf gmp-${GMP_VERSION}.tar.bz2 && \
    cd gmp-${GMP_VERSION} && \
    ./configure --prefix=$PREFIX && \
    make && make install

    cd /tmp &&
    curl --fail -sSL -O https://ftp.gnu.org/gnu/nettle/nettle-${NETTLE_VERSION}.tar.gz && \
    tar xf nettle-${NETTLE_VERSION}.tar.gz && \
    cd nettle-${NETTLE_VERSION} && \
    ./configure --prefix=$PREFIX \
      --with-lib-path=$PREFIX/lib \
      --with-include-path=$PREFIX/include \
      --disable-openssl && \
    make && make install

else
    echo Manylinux2020 build
    sudo apt-get update
    sudo apt-get install -yqq cargo clang git nettle-dev pkg-config libssl-dev openssl libpcsclite-dev llvm gcc-multilib libgmp-dev libgmp3-dev
fi
