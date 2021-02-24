# KEVLAR-TZ: a Secure Cache for ARM TrustZone

KEVLAR-TZ implements a cache inside an OP-TEE trusted application to reduce the amount of queries done to persistent storage. KEVLAR-TZ has currently been tested on Raspberry Pi 3 Model B+ and on QEMU version 8.

## Build and run

KEVLAR-TZ is designed to be compiled as part of [OP-TEE][]. To do so, follow the instructions on the [OP-TEE's documentation][docs] to install all the dependencies and build the OS for the platform you want. This process should have created a directory `optee_examples` inside the OP-TEE root folder, clone this repository there (`optee/optee_examples/kevlar-tz`) and build the OS following the instructions on their documentation. The KEVLAR-TZ binary will be under `/usr/bin/kevlar-tz`.

### Running with MQT-TZ

To run KEVLAR-TZ along with [MQT-TZ][], download MQT-TZ and follow the instructions on [mqttz/mqttz-br-package][] to use it with OP-TEE. Once you have successfully compiled both, first run the MQT-TZ broker and then KEVLAR-TZ, the TCP connection will be done automatically and you'll be able to use the broker normally.

## Acknowledgements

This work is supported in part by Moore4Medical, which has received funding within the Electronic Components and Systems for European Leadership Joint Undertaking (ECSEL JU) in collaboration with the European Union's H2020 framework Programme (H2020/2014-2020) and National Authorities, under grant agreement H2020-ECSEL-2019-IA-876190. Moreover, this project has received funding from the European Union's Horizon 2020 research and innovation programme under grant agreement No 766733.


[OP-TEE]: <https://www.op-tee.org/>
[docs]: <https://optee.readthedocs.io>
[MQT-TZ]: <https://github.com/mqttz/mqttz>
[mqttz/mqttz-br-package]: <https://github.com/mqttz/mqttz-br-package>
