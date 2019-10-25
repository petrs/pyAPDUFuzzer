#!/usr/bin/env bash

# exit when any command fails
set -e

# get the kernel name
KERNEL="$(uname)"

# install required dependencies
case $KERNEL in
    Linux)
        # get the distribution name
        LINUX_DISTRO="$(awk -F= \
                     '/^NAME/{gsub(/"/,"",$2);print($2)}' \
                     /etc/os-release)"

        case $LINUX_DISTRO in
            Fedora)
                sudo dnf install -y \
                    git \
                    gcc \
                    python3 \
                    python3-devel \
                    python3-pip \
                    swig \
                    pcsc-lite \
                    pcsc-lite-devel \
                    american-fuzzy-lop
                ;;
            Ubuntu)
                sudo apt-get update
                sudo apt-get install -y \
                    git \
                    gcc \
                    python3 \
                    python3-dev \
                    python3-pip \
                    python3-setuptools \
                    swig \
                    pcscd \
                    libpcsclite-dev \
                    afl
                ;;
            *)
                echo 'Your Linux distribution is not currently supported.'
                echo 'Try manual installation.'
                exit 1
                ;;
        esac
        ;;

    Darwin)
        brew update
        brew install \
            git \
            gcc \
            python3 \
            swig \
            pcsc-lite \
            afl-fuzz \
        || true
        ;;
    *)
        echo 'Your operating system is not currently supported.'
        echo 'Try manual installation.'
        exit 1
        ;;
esac

# install modified version of python-afl
pip3 install --user git+https://github.com/ph4r05/python-afl

