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
| ECDSA          | P-192, P-224,    |
|                | P-256, P-384,    |
|                | P-521 curves     |
|                +------------------+
|                | Sign, verify     |
+----------------+------------------+

Symmetric Cryptography
~~~~~~~~~~~~~~~~~~~~~~

Ciphering Algorithms
++++++++++++++++++++

+----------------+----------------+----------------+
| Algorithm      | Key Size       | IV Length      |
+================+================+================+
| AES-CBC        | 128 bits       | 16 bytes       |
|                +----------------+----------------+
|                | 192 bits       | 16 bytes       |
|                +----------------+----------------+
|                | 256 bits       | 16 bytes       |
+----------------+----------------+----------------+

Authentication Algorithms
+++++++++++++++++++++++++

+----------------+------------------+---------------+---------------+
| Algorithm      | Key Size         | Digest Length | IV Length     |
+================+==================+===============+===============+
| SHA1           | N/A              | 20 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-224       | N/A              | 28 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-256       | N/A              | 32 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-384       | N/A              | 48 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-512       | N/A              | 64 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-224       | N/A              | 28 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-256       | N/A              | 32 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-384       | N/A              | 48 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-512       | N/A              | 64 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA1-HMAC      | 1 - 1024 bytes   | 20 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-224-HMAC  | 1 - 1024 bytes   | 28 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-256-HMAC  | 1 - 1024 bytes   | 32 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-384-HMAC  | 1 - 1024 bytes   | 48 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA2-512-HMAC  | 1 - 1024 bytes   | 64 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-224-HMAC  | 1 - 1024 bytes   | 28 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-256-HMAC  | 1 - 1024 bytes   | 32 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-384-HMAC  | 1 - 1024 bytes   | 48 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-512-HMAC  | 1 - 1024 bytes   | 64 bytes      | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-SHAKE-128 | 1 - 1024 bytes   | 1 - 255 bytes | N/A           |
+----------------+------------------+---------------+---------------+
| SHA3-SHAKE-256 | 1 - 1024 bytes   | 1 - 255 bytes | N/A           |
+----------------+------------------+---------------+---------------+
| AES-CMAC       | 16 bytes         | 1 - 16 bytes  | N/A           |
+----------------+------------------+---------------+---------------+
| AES-GMAC       | 128 bits         | 16 bytes      | 12 bytes      |
|                +------------------+               +               +
|                | 192 bits         |               |               |
|                +------------------+               +               +
|                | 256 bits         |               |               |
+----------------+------------------+---------------+---------------+

AEAD Algorithms
+++++++++++++++

+-----------------+----------------+---------------+---------------+-----------------+
| Algorithm       | Key Size       | Digest Length | IV Length     | AAD Length      |
+=================+================+===============+===============+=================+
| AES-CCM         | 128 bits       | 8 bytes       | 7 - 13 bytes  | 0 - 1024 bytes  |
|                 +----------------+               +               +                 +
|                 | 192 bits       |               |               |                 |
|                 +----------------+               +               +                 +
|                 | 256 bits       |               |               |                 |
+-----------------+----------------+---------------+---------------+-----------------+
| AES-GCM         | 128 bits       | 16 bytes      | 12 bytes      | 0 - 1024 bytes  |
|                 +----------------+               +               +                 +
|                 | 192 bits       |               |               |                 |
|                 +----------------+               +               +                 +
|                 | 256 bits       |               |               |                 |
+-----------------+----------------+---------------+---------------+-----------------+
| CHACHA-POLY1305 | 256 bits       | 16 bytes      | 12 bytes      | 0 - 1024 bytes  |
+-----------------+----------------+---------------+---------------+-----------------+

Random Number Generation (RNG)
++++++++++++++++++++++++++++++

+------------------+-------------+------------------+------------------+
| RNG Mode         | Input Data  | Max Random Data  | Notes            |
|                  | Required    | Length           |                  |
+==================+=============+==================+==================+
| HW_RANDOM        | None        | 32767 bytes      | Hardware-based   |
|                  |             |                  | true random      |
|                  |             |                  | number           |
|                  |             |                  | generation       |
+------------------+-------------+------------------+------------------+

.. note::
   * Only HW RANDOM RNG mode is currently supported.
   * The maximum random data length is limited by 32727 bytes.
   * Hardware Random RNG provides "true" random numbers generated from RNG circuit with a high amount of entropy.

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
#. ``dao_liquid_crypto_enq_op_ecdsa_sign`` : Enqueue ECDSA signing operation.
#. ``dao_liquid_crypto_enq_op_ecdsa_verify`` : Enqueue ECDSA verification operation.

Enqueue API - Symmetric Crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following API is used to enqueue symmetric cryptographic operations:

* ``dao_liquid_crypto_sym_enqueue_burst()``: Enqueue a burst of symmetric cryptographic operations.

Enqueue API - Random Number Generation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following API is used to enqueue random number generation operations:

* ``dao_liquid_crypto_enq_op_random()``: Enqueue a hardware-based random number generation operation.

Buffer Usage
++++++++++++

DAO Liquid Crypto Library allows the user to provide fragmented buffers for
cryptographic operations. The user can provide a list of buffers for each operation, and the
library will handle the fragmentation and reassembly of the buffers internally. This allows for
efficient memory usage and reduces the overhead of copying data between buffers.

Following represents the dao_lc_sym_op structure that is used to enqueue symmetric
cryptographic operations:

.. literalinclude:: ../../../lib/liquid_crypto/dao_liquid_crypto.h
   :language: c
   :start-after: Structure dao_lc_sym_op 8<
   :end-before: >8 End of structure dao_lc_sym_op.

**Data Buffers**:
	Pointers to the input and output data buffers for the operation are specified using
	``dao_lc_sym_op.in_buffer`` (input buffer) and ``dao_lc_sym_op.out_buffer`` (output buffer).
	If ``dao_lc_sym_op.out_buffer`` is set to NULL, the operation is performed in-place, and the
	input buffer is used as both the source and destination.

	Both input and output buffers can be fragmented; the library manages fragmentation and
	reassembly internally. Cryptographic operations are applied only to the regions of the
	buffer specified by the cipher and authentication offsets and lengths, not to the entire
	buffer.

**AEAD Operations**:
	The ``dao_lc_sym_op`` structure supports AEAD (Authenticated Encryption with Associated Data)
	operations, such as AES-GCM, which perform encryption and authentication simultaneously.
	For AEAD operations:

	- ``cipher_offset`` and ``cipher_len`` specify the region of the input buffer to be encrypted
	  and authenticated.
	- The ``aad`` field provides additional authenticated data that is not encrypted but is
	  included in the authentication calculation.
	- The ``cipher_iv`` field supplies the initialization vector (IV) required for the cipher
	  operation.
	- The ``digest`` field is used to store or verify the authentication tag (also known as the
	  authentication digest). For encryption, the tag is generated and written to ``digest``; for
	  decryption, the tag in ``digest`` is verified. If ``digest`` is NULL, the authentication tag
	  is expected to be located immediately after the ciphered data in the buffer.

	The library manages all AEAD-specific processing internally, including handling of fragmented
	buffers and correct placement of the authentication tag.

	In case of out-of-place operations, the output buffer contains the ciphered data and, if the
	``digest`` field is NULL, the authentication tag as well. The input buffer remains unchanged.
	Ciphered data is copied to the output buffer starting from the offset defined by
	``cipher_offset`` and for a length of ``cipher_len``.

	In case of in-place operations, the input buffer is overwritten with the ciphered data starting
	at the offset specified by ``cipher_offset`` for a length of ``cipher_len``. If ``digest`` is
	NULL, the authentication tag (for encrypt operations) is written immediately after the
	ciphered data in the buffer. For decrypt operations, if the ``digest`` field is NULL, the
	authentication tag is expected to be located immediately after the ciphered data in the buffer
	and is used for verification.

	The fields, ``auth_offset``, ``auth_len``, and ``auth_iv``, are ignored for AEAD
	operations.

**Cipher Only Operations**:
	The ``dao_lc_sym_op`` structure supports cipher-only operations, such as symmetric
	ciphering algorithms like AES-CBC. For these operations:

	- ``cipher_offset`` and ``cipher_len`` specify the offset and length of the data within the
	  input buffer to be encrypted or decrypted.
	- ``cipher_iv`` provides the initialization vector (IV) required for the cipher operation.

	In case of out-of-place operations, the output buffer contains the ciphered data, while the
	input buffer remains unchanged. The ciphered data is copied to the output buffer starting at
	the offset specified by ``cipher_offset`` and for a length of ``cipher_len``.

	In case of in-place operations, the input buffer is overwritten with the ciphered data,
	starting from the offset specified by ``cipher_offset`` and for a length of ``cipher_len``.

	All authentication-related fields (``auth_offset``, ``auth_len``, ``auth_iv``, ``aad``, and
	``digest``) are ignored for cipher-only operations.

**Auth Only Operations**:
	The ``dao_lc_sym_op`` structure supports authentication-only operations, such as hashing
	algorithms like SHA1. For these operations, the ``auth_offset`` and ``auth_len`` fields
	specify the offset and length of the data to be authenticated within the input buffer.

	- ``auth_offset`` and ``auth_len`` specify the region of the input buffer to be authenticated.
	- ``auth_iv`` provides the initialization vector (IV) required for the authentication
	  operation. This field is optional and should be set only if the authentication algorithm
	  requires an IV.
	- ``digest`` is used to store the generated authentication tag (for auth_gen operations)
	  or to provide the tag to be verified (for auth_verify operations). The ``digest`` field
	  must always be set (not NULL) for authentication-only operations.

	In authentication-only operations, the ``out_buffer`` field is not used. The input buffer
	is not modified, and the authentication tag is written to the ``digest`` field.

	All cipher and AEAD-related fields (``cipher_offset``, ``cipher_len``, ``cipher_iv``, and
	``aad``) are ignored for authentication-only operations.

**Cipher and Auth Operations**:
	The ``dao_lc_sym_op`` structure supports combined cipher and authentication operations,
	such as AES-CBC with SHA1-HMAC. These are often called "chained" operations,
	where both ciphering and authentication are performed on specified regions of the input
	buffer. The order of operations (encrypt-then-authenticate or authenticate-then-encrypt)
	is determined by the session configuration. In these operations, both ciphering and
	authentication are applied to specified regions of the input buffer, as defined by:

	- ``cipher_offset`` and ``cipher_len``: Offset and length of the data to be encrypted or
	  decrypted.
	- ``auth_offset`` and ``auth_len``: Offset and length of the data to be authenticated.
	- ``cipher_iv``: Initialization vector for the cipher operation.
	- ``auth_iv``: Initialization vector for the authentication operation (if required).
	- ``digest``: Pointer to the authentication tag (for encrypt/auth_gen) or the tag to be
	  verified (for decrypt/auth_verify).

	The library manages the sequencing and data flow, ensuring that cipher and authentication
	steps are performed in the correct order as specified in the session configuration. Both
	in-place and out-of-place buffer modes are supported. Handling of the authentication tag
	(``digest``) follows the same rules as described for other operation types.

	If the ``digest`` field is NULL, the authentication tag is expected to be located
	immediately after the ciphered data in the buffer. If ``digest`` is not NULL, the
	authentication tag is generated and stored in the ``digest`` field (for encrypt/auth_gen
	operations) or verified against the ``digest`` field (for decrypt/auth_verify operations),
	regardless of whether the operation is in-place or out-of-place.

	For out-of-place operations, the output buffer contains the ciphered and/or authenticated
	data, and, if ``digest`` is NULL, the authentication tag as well. The input buffer remains
	unchanged. Ciphered data is copied to the output buffer starting at ``cipher_offset`` for
	``cipher_len`` bytes. Authenticated data is copied to the output buffer starting at
	``auth_offset`` for ``auth_len`` bytes.

	For in-place operations, the input buffer is overwritten with the ciphered data starting at
	``cipher_offset`` for ``cipher_len`` bytes, followed by the authentication tag if
	``digest`` is NULL.

**Summary of Fields**:
	The following table summarizes the fields in the ``dao_lc_sym_op`` structure and their
	applicability for different types of operations:

	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| Field             | Description         | AEAD  | Cipher only | Auth only | Cipher-Auth |
	+===================+=====================+=======+=============+===========+=============+
	| ``cipher_offset`` | Cipher Offset       | **R** | **R**       | *NA*      | **R**       |
	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| ``cipher_len``    | Cipher Length       | **R** | **R**       | *NA*      | **R**       |
	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| ``auth_offset``   | Authentication      | *NA*  | *NA*        | **R**     | **R**       |
	|                   | Offset              |       |             |           |             |
	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| ``auth_len``      | Authentication      | *NA*  | *NA*        | **R**     | **R**       |
	|                   | Length              |       |             |           |             |
	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| ``cipher_iv``     | Cipher IV           | **R** | **R**       | *NA*      | **R**       |
	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| ``auth_iv``       | Authentication IV   | *NA*  | *NA*        | O         | O           |
	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| ``aad``           | Additional          | O     | *NA*        | *NA*      | *NA*        |
	|                   | Authentication Data |       |             |           |             |
	+-------------------+---------------------+-------+-------------+-----------+-------------+
	| ``digest``        | Digest              | O     | *NA*        | **R**     | O           |
	+-------------------+---------------------+-------+-------------+-----------+-------------+

.. note::

	- **R**: Required field for the operation.
	- **O**: Optional field for the operation.
	- **NA**: Not applicable for the operation.

Dequeue API
~~~~~~~~~~~

The following API is used to dequeue liquid crypto operations:

* ``dao_liquid_crypto_dequeue_burst()``: Dequeue a burst of liquid crypto operations.

Known Limitations
-----------------

#. If the device is stopped & started without doing a device teardown (fini), then invalid results
   can be received.
