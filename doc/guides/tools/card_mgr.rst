..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

DAO Card Manager
================

DAO Card Manager is a user-space application designed to manage DAO cards and provide a
comprehensive interface for configuring and monitoring DAO-supported offload cards. It delivers
management services, allowing users to configure card settings, monitor operational status, and
efficiently manage card resources. This facilitates streamlined deployment, maintenance, and
optimization of DAO cards in supported environments.

Supported Platforms
-------------------

DAO Card Manager is supported on the following platforms:

- **LiquidCrypto (LC)**

Architecture
-------------

.. figure:: img/card_mgr_block_diag.svg
   :align: center
   :alt: Card Manager Block Diagram

DAO Card Services are implemented on top of gRPC protocol. DAO Card Library offers a set of APIs
that allows users to interact with DAO cards. DAO Card Manager offers a user-friendly interface for
management operations in DAO Card Library.

Using DAO Card Manager
----------------------

Build
~~~~~

DAO Card Manager will get built as part of the DAO build process. DAO Card Manager gets built
only if DAO is built for host environment and all the dependencies are met.

.. code-block:: console

    $ meson setup build
    $ ninja -C build
    $ ls build/app/dao-card-mgr

Launching Card Manager
~~~~~~~~~~~~~~~~~~~~~~

DAO Card Manager follows a client-server architecture. The same application 'dao_card_mgr' can be
run as a server or as a client. The server establishes gRPC connection with the card and listens for
incoming requests from card manager clients.

To launch DAO Card Manager as a server, use the following command:

.. code-block:: console

    $ ./build/app/dao-card-mgr -s
    $ [lcore -1] DAO_INFO: Starting as server

To launch DAO Card Manager as a client, use the following command:

.. code-block:: console

    $ ./build/app/dao-card-mgr -c
    $ [lcore -1] DAO_INFO: Starting as client
    $ ?

Once the client is launched, various commands can be executed to manage DAO cards.

.. note:: Root Privileges (Enforced)

   ``dao_card_mgr`` performs a hard check at startup and will exit immediately if the effective
   user ID is not ``root``. This is because several commands (e.g. *card_boot_source*,
   *card_app_update*,  *card_fw_update*, *card_failsafe_update*, *card_mcu_update*) require
   unloading / reloading kernel modules and configuring network interfaces as part of the reboot or
   bring-up sequence. These operations fundamentally require full root privileges; partial
   capabilities are not accepted.

   Action recommended: always run both the server and client instances of ``dao_card_mgr`` as ``root``.
   Invoking the program as a non-root user will terminate immediately with an explanatory message.

Management Services
-------------------

Configuration
~~~~~~~~~~~~~

DAO Card Manager provides a set of commands to manage DAO cards. The following commands are
available:

* ``card_init``

   This command initializes the DAO card and prepares it for operation. It sets up the card's
   initial state and ensures it is ready to handle requests. Note that this command must be executed
   before any other commands can be run on the card.

* ``card_info``

   This command retrieves information about the DAO card, including its capabilities, status,
   and configuration. It provides essential details that help users understand the current state
   of the card.

* ``card_boot_source <main|failsafe> <file_path>/mrvl-oct-boot``

   This command immediately boots the DAO card to the specified source image. The first argument
   selects the boot mode: ``main`` for the standard image, ``failsafe`` for the recovery image. The
   second argument specifies the full path to the ``mrvl-oct-boot`` binary used to perform the boot
   operation.

   After issuing this command, the card manager reloads the firmware and waits for the card to
   become ready before returning to the CLI prompt.

**Example:**
   .. code-block:: console

      card_boot_source main /tmp/mrvl-oct-boot
      card_boot_source failsafe /tmp/mrvl-oct-boot


* ``card_fini``

   This command finalizes the DAO card, cleaning up resources and preparing it for shutdown.
   It is important to run this command before stopping the card manager to ensure that all
   resources are properly released. No commands can be run on the card after this command
   is executed. Card reboot is required to reinitialize the card.

.. _diagnostics:

Diagnostics
~~~~~~~~~~~

DAO Card Manager provides diagnostic commands to help users monitor and troubleshoot DAO cards. The
following commands are available for diagnostics:

* ``card_stats``

   This command retrieves statistics from the DAO card, including per LC-core packet counts and
   other operational metrics. It helps users monitor the card's performance and diagnose issues
   such as packet drops or uneven load distribution.

* ``card_dmesg``

   Retrieves a truncated tail (recent portion) of the card kernel dmesg log through the gRPC
   service. If the deployed server version does not support the RPC the manager reports an
   "unsupported" error.
   Output size is capped (currently ~64KB) to avoid excessive transfer.

* ``card_applog``

   Fetches the current application (crypto agent) log contents. If the log file is not present, an
   empty result is returned (treated as success). Intended for quick inspection without direct file
   access to the card filesystem.

Above options are supported on all DAO cards where the underlying firmware exposes the respective RPCs.

.. _firmware_management:

Firmware Management
~~~~~~~~~~~~~~~~~~~

DAO Card Manager also supports firmware management for DAO cards. The following commands are
available for managing firmware:

* ``card_app_update <file_path>/app.tar <file_path>/mrvl-oct-boot``

   This command updates only the application partition of the DAO card firmware. The ``<filename>``
   argument specifies the full path to the file to upload. The second argument specifies the full
   path to the ``mrvl-oct-boot`` binary used to perform the boot operation.
   Use this command to update DAO applications in the firmware without updating the complete
   firmware.

**Example:**
   .. code-block:: console

      card_app_update /tmp/app.tar /tmp/mrvl-oct-boot

   Supported only when the card is booted with the 'main' image. After a successful update, the
   manager automatically reloads the firmware helper (``mrvl-oct-boot``) and waits
   (up to ~20 seconds) for the card to become ready before returning to the CLI prompt.

   This command is supported on LiquidCrypto (LC) cards.

* ``card_app_fallback``

   This command switches the application images used by the 'main' image on LiquidCrypto card.
   This command is useful for recovery scenarios when an application image updated using
   ``card-app_update`` fails to start.
   The command is only supported when the card is booted from the 'failsafe' image.

   If the card is not in SPI boot mode, the command will return an error.

* ``card_fw_update <file_path>/main_fw.tar <file_path>/mrvl-oct-boot``

   This command updates the complete DAO card firmware. The ``<filename>`` argument specifies the
   full path to the firmware file to upload. The second argument specifies the full path to the
   ``mrvl-oct-boot`` binary used to perform the boot operation.
   Use this command to update all firmware partitions, including the application and system
   partitions (i.e: kernel and root filesystem).

**Example:**
   .. code-block:: console

      card_fw_update /tmp/main_fw.tar /tmp/mrvl-oct-boot

   Supported only when the card is booted with the 'failsafe' image. After a successful update the
   manager reloads using the provided boot binary (``mrvl-oct-boot``) targeting the 'main' image and
   waits for readiness.
   If the card was already in 'main' boot mode this command is rejected (permission error).

   This command is supported on LiquidCrypto (LC) cards.

* ``card_failsafe_update <file_path>/failsafe_fw.img <file_path>/mrvl-oct-boot``

   This command updates the failsafe image on the DAO card. The ``<filename>`` argument specifies
   the full path to the failsafe image file to upload. The second argument specifies the full path
   to the ``mrvl-oct-boot`` binary used to perform the boot operation.

  **Example:**
   .. code-block:: console

      card_failsafe_update /tmp/failsafe_fw.img /tmp/mrvl-oct-boot

   Supported only when the card is booted with 'main' image. The update can take approximately 10 to
   12 minutes. After a successful update the manager reloads into the 'failsafe' context and waits
   for readiness before returning. The command verifies the integrity of the uploaded image using a
   checksum before flashing.

   This command is supported on LiquidCrypto (LC) cards.

* ``card_mcu_update <file_path>/mcu_fw.bin``

   Updates the MCU / controller firmware component packaged for the card. Use this for low-level
   controller microcode / support processor updates that do not require full firmware replacement.

   **Example:**
   .. code-block:: console

      card_mcu_update /tmp/mcu_fw.bin

   Only allowed in 'main' boot mode; denied in 'failsafe'. If an MCU update script fails, the CLI
   reports an aborted error status.

For more details on partition layout of LiquidCrypto (LC) cards, see
:ref:`LiquidCrypto Partitioning <liquidcrypto_partitioning>`.
