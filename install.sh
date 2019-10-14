#!/usr/bin/env bash

# check if script is run with super-user privileges
if [[ $EUID -ne 0 ]]; then
    echo 'This script must be run as root!'
    exit 1
fi

# exit when any command fails
set -e

# get distribution name
DISTRO="$(awk -F= '/^NAME/{gsub(/"/,"",$2);print($2)}' /etc/os-release)"

# install required dependencies
case $DISTRO in
    Fedora)
        dnf install -y \
                git \
                gcc \
                python2 \
                python3 \
                python3-pip \
                python3-devel \
                swig \
                pcsc-lite \
                pcsc-lite-devel \
                american-fuzzy-lop
        ;;
    Ubuntu)
        apt-get update
        apt-get install -y \
                git \
                gcc \
                python2.7 \
                python3 \
                python3-pip \
                python3-dev \
                swig \
                pcscd \
                libpcsclite-dev \
                afl
        ;;
esac

# install modified version of python-afl
pip3 install git+https://github.com/ph4r05/python-afl

# install pyAPDUFuzzer
sudo -u "$SUDO_USER" git clone https://github.com/petrs/pyAPDUFuzzer.git
cd pyAPDUFuzzer && python3 setup.py install && cd ..

