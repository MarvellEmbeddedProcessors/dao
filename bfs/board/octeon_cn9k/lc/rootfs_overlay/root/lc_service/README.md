# DAO Crypto Agent Application

## Overview
The dao-crypto-agent is a userspace application that processes packets received
from the host. Depending on the operation type, it either submits the packet to
CPT for encryption or decryption, or bypasses the CPT. It then dequeues the
packets and sends them back to the host.

## Running the Application as a init Service
## lc service
The `lc_service` will be launched as an init service, creating the necessary
environment required for the crypto agent application.

It will start the `cp agent` as a background application, enabling communication
with the host.

The service will assign a static IP and brings up the network interface. By
default it will assign `192.168.1.100` as the IP address. User can specify a
different IP by setting the `IP_ADDRESS` value in `lc_env` configuration file.
The board needs to be rebooted for the changes to take effect.

Based on argument value in `lc_env` the service will either launch the crypto
agent, initiate stress test or simply exit the daemon.

All the script and configuration files are located in `/root/lc_service/`
directory.

## Required files by lc service
1. `S99lc`             :  Init service file. Installed in `/etc/system.d`.
                          It invokes the main service script file in background.
2. `lc_service.sh`     :  Main service script file.
3. `lc_env_setup.sh`   :  Loads the modules, setsup the hugepages and launches
                          cp agent.
4. `lc_crypto_agent.sh`:  Script file launches crypto agent application.
5. `lc_stress_test.sh` :  Script file launches stress test.
6. `lc_devbind.sh`     :  Script file binds the devices to vfio.
7. `dma_config.ini`    :  Config file required by stress test.
8. `lc_env`            :  Config file required by `lc_service.sh`.

# Using Config File to Control the Launch of Application
The `lc_env` configuration file controls which application to launch:

- `$ARGUMENT=run_agent`      : Launches the dao-crypto-agent application.
- `$ARGUMENT=run_stress_test`: Launches the stress test.
- `$NUM_ITR=<value>`         : Valid only for the stress test. The test will iterate `<value>` times.
- `$ARGUMENT=skip`           : Does not launch any application and exits the daemon.
- `$IP_ADDRESS=<value>`      : Static IP address to be configured.

After any update to the `lc_env` file, a reboot is required for the changes to take effect.
