# KEVLAR-TZ: a Secure Cache for ARM TrustZone

KEVLAR-TZ implements a cache inside an OP-TEE trusted application to reduce the
amount of queries done to persistent storage. KEVLAR-TZ has currently been
tested on Raspberry Pi 3 Model B+ and on QEMU version 8.

## Build and run

KEVLAR-TZ is designed to be compiled as part of [OP-TEE][]. To build and run
OP-TEE with KEVLAR-TZ, you can simply run the script `install.sh` on this
repository (only tested on Ubuntu 20.04):

```
https://raw.githubusercontent.com/mqttz/kevlar-tz/master/install.sh | bash -s qemu
```

You can change `qemu` for `rpi3` and it will do the installation for the
Raspberry Pi. The script will print information on how to continue.

### Manual installation

If you are not running Ubuntu 20.04 or want to install OP-TEE and KEVLAR-TZ
manually, you can following these steps:

1. Build and run OP-TEE (follow the instructions [here][i1] and [here][i2]).
   This will download all the necessary files and put them all inside the
   directory specified during the installation.
2. Go to `<optee-project>/optee_examples` and clone the KEVLAR-TZ repository
   there:
   ```
   cd <optee-project>/optee_examples
   git clone https://github.com/mqttz/kevlar-tz
   ```
3. Build OP-TEE again:
   ```
   cd <optee-project>/build
   make -j `nproc`
   ```
4. Install the OS on the device you'll be using. (If you will run it on QEMU
   this step is not necessary). 
5. Run the OS and login as `root`, the binary for KEVLAR-TZ can be found at
   `/usr/bin/kevlar-tz` and can be executed using:
   ```
   kevlar-tz
   ```
   or with the absolute path
   ```
   /usr/bin/kevlar-tz
   ```
   If you want to run it using QEMU, running `make run` inside the
   `<optee-project>/build` directory will build the OS and start QEMU.

### Running with MQT-TZ

To run KEVLAR-TZ along with [MQT-TZ][], download MQT-TZ and follow the
instructions on [mqttz/mqttz-br-package][] to use it with OP-TEE. Once you have
successfully build OP-TEE with both programs, login as root and run the
following:

```
mosquitto &
kevlar-tz &
```

The first command start the MQT-TZ broker, and the second one starts KEVLAR-TZ
(which will automatically connect to the broker using TCP). You will now be able
to use the broker normally.

## Acknowledgements

This work is supported in part by Moore4Medical, which has received funding
within the Electronic Components and Systems for European Leadership Joint
Undertaking (ECSEL JU) in collaboration with the European Union's H2020
framework Programme (H2020/2014-2020) and National Authorities, under grant
agreement H2020-ECSEL-2019-IA-876190. Moreover, this project has received
funding from the European Union's Horizon 2020 research and innovation programme
under grant agreement No 766733.


[OP-TEE]: <https://www.op-tee.org/>
[i1]: <https://optee.readthedocs.io/en/latest/building/index.html>
[i2]: <https://optee.readthedocs.io/en/latest/building/gits/build.html#get-and-build-the-solution>
[MQT-TZ]: <https://github.com/mqttz/mqttz>
[mqttz/mqttz-br-package]: <https://github.com/mqttz/mqttz-br-package>
