#!/usr/bin/env bash

if [ -f /usr/bin/yum ]; then
    yum install -y pcsc-lite-devel
else
    apt-get update
    apt-get install -yqq libpcsclite-dev
fi
