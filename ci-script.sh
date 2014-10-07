#!/bin/bash

apt-cache search daq

# Install ODP first
git clone http://git.linaro.org/git/lng/odp.git odp.git
./bootstrap
./configure --prefix=$(PWD)/../odp-bin --with-pic
make
make install

# Now build DAQ-ODP
autoreconf -ivf
./configure --with-odp-path=$(PWD)/../odp-bin
make
