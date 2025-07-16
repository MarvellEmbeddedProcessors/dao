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

* ``card_boot_source <main|failsafe> <path-to-mrvl-oct-boot>``

   This command configures the DAO card to boot from either the 'main' or 'failsafe' image on the
   next reboot. The first argument selects the boot mode: ``main`` for the standard image,
   ``failsafe`` for the recovery image. The second argument specifies the full path to binary
   ``mrvl-oct-boot`` which configures the DAO card.

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

.. _firmware_management:

Firmware Management
~~~~~~~~~~~~~~~~~~~

DAO Card Manager also supports firmware management for DAO cards. The following commands are
available for managing firmware:

* ``card_app_update <filename>``

   This command updates only the application partition of the DAO card firmware. The ``<filename>``
   argument specifies the full path to the file to upload. Use this command to update DAO
   applications in the firmware without updating the complete firmware. The card must be restarted
   after the update to apply the changes.

   Note that this command is only supported when the card is booted with 'main' image and is
   initialized  with ``card_init`` command. If the card is booted with 'failsafe' image, this
   command will not work and will return an error.

   This command is supported on LiquidCrypto (LC) cards.

* ``card_fw_update <filename>``

   This command updates the complete DAO card firmware. The ``<filename>`` argument specifies the
   full path to the firmware file to upload. Use this command to update all firmware partitions,
   including the application and system partitions (i.e: kernel and root filesystem).

   Note that this command is only supported when the card is booted with 'failsafe' image and is
   initialized with ``card_init`` command. The card must be restarted with 'main' image to apply
   the changes.
   If the card is booted with 'main' image, this command will not work and will return an error.

   This command is supported on LiquidCrypto (LC) cards.

Above options are supported on all DAO cards.

For more details on partition layout of LiquidCrypto (LC) cards, see
:ref:`LiquidCrypto Partitioning <liquidcrypto_partitioning>`.
