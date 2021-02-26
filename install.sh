#!/usr/bin/env bash

set -e

err_exit() { printf "Error on line $(caller).\nExiting.\n" ; }

trap "err_exit" ERR

if [ "$1" = "rpi3" ]; then
    TARGET="rpi3"
elif [ "$1" = "qemu" ]; then
    TARGET="qemu_v8"
else
    cat<<EOF
Usage: $0 TARGET

Script for Ubuntu 20.04 that installs all dependencies and builds OP-TEE with
KEVLAR-TZ.

TARGET options:

    rpi3        Raspberry Pi 3 Model B or B+
    qemu        QEMU v8
EOF
    exit 1
fi

# Install Android repo - https://source.android.com/setup/build/downloading
sudo sh -c 'curl https://storage.googleapis.com/git-repo-downloads/repo > /usr/local/bin/repo'
sudo chmod +x /usr/local/bin/repo

# Install OP-TEE prerequisites - https://optee.readthedocs.io/en/latest/building/prerequisites.html#prerequisites
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt install -y uuid-dev python3-pyelftools libglib2.0-dev libpixman-1-dev \
    python2 ccache iasl flex bison python3-pip ccache libssl-dev unzip
sudo python3 -m pip install pycryptodome pycryptodomex

# Link python -> python2 if not already done
set +e
sudo ln -s "$(which python2)" /usr/bin/python
set -e

# Configure git if not already done
git config --global user.name || git config --global user.name "name"
git config --global user.email || git config --global user.email "email"
git config --global color.ui || git config --global color.ui "auto"

# Installing OP-TEE
mkdir -p "optee-$TARGET"
cd "optee-$TARGET"
repo init -u https://github.com/OP-TEE/manifest.git -m "$TARGET.xml"
repo sync -j4 --no-clone-bundle
cd optee_examples
git clone https://github.com/mqttz/kevlar-tz
cd ../build
make -j2 toolchains
make -j `nproc`

cat<<EOF

--------------------------------------------------------------------------------

EOF

if [ "$TARGET" = "rpi3" ]; then
    cat<<EOF
The program has been successfully installed and built. Now you need to get it
into the Raspberry Pi. To do so, follow the instructions on the following link
(starting at step 2):

    https://optee.readthedocs.io/en/latest/building/devices/rpi3.html#build-instructions

You can find the build directory at $(pwd).
EOF
else
    cat<<EOF
The program has been successfully installed and built. To run it inside QEMU,
execute the following:

    cd $(pwd)
    make run-only

If you want to recompile before executing, run 'make run' instead.
EOF
fi

cat<<EOF

Once the system has booted, login as 'root' (no password). The kevlar-tz
executable can be found at '/usr/bin/kevlar-tz'. You can run it by typing
'kevlar-tz' on the terminal.

Note: if you hadn't configured the setting user.name, user.email or color.ui in
Git, they have been set to "name", "email" and "auto", respectively, change them
by editing the Git config file or by running:

    git config --global <setting> "value"

For example:

    git config --global user.name "My Name"
EOF
