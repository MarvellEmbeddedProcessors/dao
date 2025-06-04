..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

*********************
Liquid Crypto Library
*********************

Liquid crypto library provides a set of cryptographic primitives that can be used to offload
cryptographic operations to hardware accelerators. The library is optimized for performance
and low power consumption.

The library provides a set of APIs for various cryptographic operations, including symmetric
encryption, hashing, and public key cryptography. The library is designed to be modular and
can be easily extended to support new algorithms and hardware accelerators.

Architecture Overview
---------------------

The Liquid Crypto Library is designed to be modular and extensible. The library is built on top of
the 'eth_transport' library from DAO, which provides a set of APIs for managing hardware
accelerators and pushing cryptographic operations to the hardware accelerators. The 'eth_transport'
library internally uses the 'rte_ethdev' library from DPDK to manage the hardware accelerators.

For more information about the 'eth_transport' library, see the :doc:`eth_transport` guide.

The Liquid Crypto Library uses a queue-based architecture to manage the execution of
cryptographic operations. The queue is used to manage the execution of cryptographic operations
in a non-blocking manner, allowing multiple operations to be executed concurrently. The library
provides a set of APIs for various cryptographic operations, including symmetric encryption,
hashing, and public key cryptography.

.. note::

    * Enqueue and dequeue operations on a queue must not be executed concurrently by different
      threads.
    * Only 2048, 4096 and 8192 queue depths are supported.

Features
--------

Asymmetric Cryptography
~~~~~~~~~~~~~~~~~~~~~~~

+----------------+------------------+
| Algorithm      | Parameters       |
+================+==================+
| RSA            | 17 - 1024 bytes  |
|                +------------------+
|                | Encrypt, decrypt |
+----------------+------------------+
| RSA-CRT        | 34 - 1024 bytes  |
|                +------------------+
|                | Encrypt, decrypt |
+----------------+------------------+

Symmetric Cryptography
~~~~~~~~~~~~~~~~~~~~~~

Ciphering Algorithms
++++++++++++++++++++

+----------------+----------------+
| Algorithm      | Key Size       |
+================+================+
| AES-CBC        | 128 bits       |
|                +----------------+
|                | 192 bits       |
|                +----------------+
|                | 256 bits       |
+----------------+----------------+

Authentication Algorithms
+++++++++++++++++++++++++

+----------------+----------------+---------------+
| Algorithm      | Key Size       | Digest Size   |
+----------------+----------------+---------------+
| SHA1           | N/A            | 20 bytes      |
+----------------+----------------+---------------+

AEAD Algorithms
+++++++++++++++

+----------------+----------------+---------------+
| Algorithm      | Key Size       | Digest Size   |
+================+================+===============+
| AES-GCM        | 128 bits       | 16 bytes      |
|                +----------------+---------------+
|                | 192 bits       | 16 bytes      |
|                +----------------+---------------+
|                | 256 bits       | 16 bytes      |
+----------------+----------------+---------------+

Control Plane
-------------

Liquid crypto library provides a set of APIs for configuring devices and managing queues. Queues
are used to submit cryptographic operations to the hardware accelerators and retrieve the results.
One device can have multiple queues, and each queue can be used to submit multiple operations.

Setup Device and Queues
~~~~~~~~~~~~~~~~~~~~~~~

The following sequence demonstrates how to use the Liquid Crypto Library APIs to perform
cryptographic operations:

1. **Initialize the Library**:
	Call the `dao_liquid_crypto_init()` function to initialize the library and prepare it for
	use.

	.. code-block:: c

		int ret;

		ret = dao_liquid_crypto_init();
		if (ret != 0) {
			 /* Handle initialization error */
		}

2. **Get Device Information**:
	Use the `dao_liquid_crypto_info_get()` function to retrieve information about the
	available devices.

	.. code-block:: c

		struct dao_lc_info info;
		int ret;

		ret = dao_liquid_crypto_info_get(device_id, &info);
		if (ret != 0) {
			 /* Handle device info retrieval error */
		}

3. **Create a Device**:
	Use the `dao_liquid_crypto_dev_create()` function to create a cryptographic device. Up to
	``dao_lc_info.nb_dev`` devices can be created.

	.. code-block:: c

		struct dao_lc_dev_conf conf;
		int ret;

		ret = dao_liquid_crypto_dev_create(&conf);
		if (ret < 0) {
			 /* Handle device creation error */
		}

4. **Calculate Size of Segments**
	Use the `dao_liquid_crypto_seg_size_calc()` function to calculate the size of the
	segments required for the features to be enabled. This segment size need to be
	configured per queue.

	.. code-block:: c

		struct dao_lc_feature_params feature_params;
		uint16_t seg_sz;

		seg_sz = dao_liquid_crypto_seg_size_calc(&params);
		if (seg_sz == 0) {
			 /* Handle segment size calculation error */
		}


4. **Configure Queue Pair**:
	Configure the queue pair for cryptographic operations using
	`dao_liquid_crypto_qp_configure()`.

	.. code-block:: c

		struct dao_lc_qp_conf qp_config;
		uint8_t dev_id = 0;
		uint16_t qp_id = 0;
		int ret;

		/* Populate the qp_config structure */
		ret = dao_liquid_crypto_qp_configure(dev_id, qp_id, &qp_config);
		if (ret != 0) {
			 /* Handle queue pair configuration error */
		}

5. **Start the Device**:
	Use `dao_liquid_crypto_dev_start()` to start the device after configuring the queue pair.
	Datapath operations can be performed only after the device is started.

	.. code-block:: c

		ret = dao_liquid_crypto_dev_start(device_id);
		if (ret != 0) {
			 /* Handle device start error */
		}

Device Teardown
~~~~~~~~~~~~~~~

1. **Stop the Device**:
	Use `dao_liquid_crypto_dev_stop()` to stop the device when it is no longer needed.

	.. code-block:: c

		ret = dao_liquid_crypto_dev_stop(device_id);
		if (ret != 0) {
			 /* Handle device stop error */
		}

2. **Destroy the Device**:
	Use `dao_liquid_crypto_dev_destroy()` to destroy the device and free any associated
	resources.

	.. code-block:: c

		ret = dao_liquid_crypto_dev_destroy(device_id);
		if (ret != 0) {
			 /* Handle device destruction error */
		}

3. **Finalize the Library**:
	Call `dao_liquid_crypto_fini()` to finalize the library and release any resources.

	.. code-block:: c

		ret = dao_liquid_crypto_fini();
		if (ret != 0) {
			 /* Handle library finalization error */
		}

.. note::

    * Once the library is finalized, all resources associated with the library are released. Library
      functions should not be called after finalization.

Command Queue
~~~~~~~~~~~~~

The command queue is used to submit command operations to the hardware accelerators. The
command queue operations are non-blocking and can be executed concurrently with the data queue
operations. A queue is designated as command queue during liquid crypto device creation using
`dao_liquid_crypto_dev_create()` by setting the 'cmd_qp_idx' field in the device
configuration structure `dao_lc_dev_conf`.

Following command operations are supported

#. Symmetric session create (``dao_liquid_crypto_sym_sess_create``)
#. Symmetric session destroy (``dao_liquid_crypto_sym_sess_destroy``)

Since the operations are performed asynchronously, the user submits the operation and polls for
completion event. The user can use the ``dao_liquid_crypto_cmd_event_dequeue`` API to poll for
completion events.

Data Plane
----------

All datapath operations are performed using the data queue. The data queue is used to submit
cryptographic operations to the hardware accelerators. The data queue operations are
non-blocking. There are multiple APIs for performing enqueue operations, while the dequeue
operation is performed using a single API.

Enqueue API - Asymmetric Crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following APIs are used to enqueue asymmetric cryptographic operations:

#. ``dao_liquid_crypto_enq_op_pkcs1v15enc`` : Enqueue PKCS1v15 encryption operation.
#. ``dao_liquid_crypto_enq_op_pkcs1v15dec`` : Enqueue PKCS1v15 decryption operation.
#. ``dao_liquid_crypto_enq_op_pkcs1v15enc_crt`` : Enqueue PKCS1v15 CRT encryption operation.
#. ``dao_liquid_crypto_enq_op_pkcs1v15dec_crt`` : Enqueue PKCS1v15 CRT decryption operation.

Enqueue API - Symmetric Crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following API is used to enqueue symmetric cryptographic operations:

* ``dao_liquid_crypto_sym_enqueue_burst()``: Enqueue a burst of symmetric cryptographic operations.

Dequeue API
~~~~~~~~~~~

The following API is used to dequeue liquid crypto operations:

* ``dao_liquid_crypto_dequeue_burst()``: Dequeue a burst of liquid crypto operations.

Known Limitations
-----------------

#. If the device is stopped & started without doing a device teardown (fini), then invalid results
   can be received.
