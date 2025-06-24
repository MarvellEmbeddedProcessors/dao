..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

DAO Liquid Crypto Performance Application
=========================================

The ``dao-liquid-crypto-perf-test`` tool is a performance benchmarking
utility designed to evaluate the performance characteristics of the LiquidCrypto card.
Currently, it supports throughput and latency performance testing, enabling users to measure
the card's data processing capabilities under various configurations.

The tool is capable of performing different types of operations, including
asymmetric cryptographic operations such as RSA encryption and decryption,
as well as passthrough operations that allow data to be sent through the card without modification.
The application is built on the DAO framework and leverages the Liquid Crypto
library to interact with the LiquidCrypto hardware.

Running the Application
-----------------------

The application provides several command-line options to customize its behavior:

.. code-block:: console

   dao-liquid-crypto-perf-test [EAL Options] -- [Application Options]

EAL Options
~~~~~~~~~~~

The following are the EAL command-line options that can be used in conjunction
with the ``dao-liquid-crypto-perf-test`` application:

* ``-c <COREMASK>`` or ``-l <CORELIST>``

	Specify the cores to use for the application. The ``COREMASK`` is a
	hexadecimal bitmask representing the cores, while the ``CORELIST`` is
	a comma-separated list of core indices.


Application Options
~~~~~~~~~~~~~~~~~~~

The following are the application-specific command-line options:

* ``--ptest <type>``

	Specify the type of performance test to run. The ``type`` can be::

	   throughput
	   latency

	This option determines the nature of the performance evaluation.

* ``--total-ops <n>``

	Specify the total number of operations to execute during the performance test.
	Replace ``<n>`` with the desired number of operations. This option allows users
	to control the workload size for benchmarking purposes.

* ``--optype <name>``

	Specify the type of operation to perform. The ``name`` can be one of the following::

	   passthrough
	      Perform a passthrough operation where data is sent through the card without modification.

	   rsa
	      Perform RSA cryptographic operations, including encryption and decryption.

	   symmetric
	      Perform symmetric cryptographic operations, such as AES encryption and decryption.

* ``--desc-nb <n>``

	Specify the number of descriptors to allocate for each LiquidCrypto device.
	This option allows users to control the number of descriptors used during
	the performance test, which can impact the throughput and resource utilization.

* ``--asym-op <pub-encrypt|pub-decrypt|prv-encrypt|prv-decrypt>``

	Specify the asymmetric cryptographic operation mode to use.
	Available options are:

	- ``pub-encrypt``: Perform public key encryption.
	- ``pub-decrypt``: Perform public key decryption.
	- ``prv-encrypt``: Perform private key encryption.
	- ``prv-decrypt``: Perform private key decryption.

	The default operation mode is ``pub-encrypt``.

* ``--rsa-priv-keytype <exp|qt>``

	Specify the RSA private key type to use for asymmetric cryptographic operations.
	This option is applicable only for RSA operations: ``prv-encrypt`` and ``prv-decrypt``.
	Available key types are:

	- ``exp``: Use the exponent-based private key.
	- ``qt``: Use the quintuple-based private key.

* ``--rsa-modlen <n>``

	Specify the RSA modulus length (in bits) for asymmetric cryptographic operations
	in the Liquid Crypto performance test. This option is applicable only for RSA operations.
	Supported lengths are:

	- ``256``: 256 bits
	- ``1024``: 1024 bits (default)
	- ``2048``: 2048 bits
	- ``4096``: 4096 bits
	- ``8192``: 8192 bits

* ``--burst-size <n>``

	Specify the burst size for each enqueue/dequeue operation. The burst size determines
	how many operations are submitted to or retrieved from the device in a single batch.
	Adjusting this value can impact performance and resource utilization. Replace ``<n>``
	with the desired burst size (e.g., 32, 64, 128).

* ``--sym-op <cipher_only|auth_only>``

	Specify the symmetric operation type to use for symmetric cryptographic operations.
	Available options are:
	- ``cipher_only``: Perform only symmetric cipher operations (e.g., AES encryption/decryption).
	- ``auth_only``: Perform only symmetric authentication operations (e.g., SHA1).

	The default symmetric operation is ``cipher_only``.

* ``--cipher-alg <aes-cbc>``

	Specify the symmetric cipher algorithm to use for symmetric cryptographic operations.
	The only supported algorithm is ``aes-cbc`` (AES in CBC mode).

	The default symmetric cipher algorithm is ``aes-cbc``.

* ``--cipher-key-sz <n>``

	Specify the symmetric cipher key size in bytes for symmetric cryptographic operations.
	Replace ``<n>`` with the desired key size (e.g., 16, 24, 32). The supported key sizes
	for AES are 16 bytes (128 bits), 24 bytes (192 bits), and 32 bytes (256 bits).

	The default symmetric cipher key size is 16 bytes (128 bits).

* ``--cipher_op <encrypt|decrypt>``

	Specify the symmetric cipher operation type to use for symmetric cryptographic operations.
	Available options are:

	- ``encrypt``: Perform encryption using the specified symmetric cipher algorithm.
	- ``decrypt``: Perform decryption using the specified symmetric cipher algorithm.

	The default operation is ``encrypt``.

* ``--auth-alg <sha1>``

	Specify the symmetric authentication algorithm to use for symmetric cryptographic operations.
	The only supported algorithm is ``sha1``.

	The default symmetric authentication algorithm is ``sha1``.

* ``--auth-op <generate|verify>``

	Specify the symmetric authentication operation type to use for symmetric cryptographic operations.
	Available options are:
	- ``generate``: Generate a symmetric authentication tag using the specified algorithm.
	- ``verify``: Verify a symmetric authentication tag using the specified algorithm.

	The default symmetric authentication operation is ``generate``.

* ``--buffer-size <n>``

	Specify the size of the data buffer in bytes for symmetric cryptographic operations.
	Replace ``<n>`` with the desired buffer size (e.g., 64, 128, 256). This option determines
	the amount of data processed in each operation. The buffer size should be a multiple of the block size
	of the symmetric cipher algorithm being used.

	The default buffer size is 64 bytes.

Examples
--------

The following are examples of how to use the ``dao-liquid-crypto-perf-test`` application for various performance tests:

1. **Throughput Test for Passthrough Operation**
	Perform a throughput test for the passthrough operation with one million total operations and 2048 descriptors::

		dao-liquid-crypto-perf-test -c 0x3 -- --total-ops 1000000 --desc-nb 2048 --optype passthrough --ptest throughput

2. **Throughput Test for RSA Encryption**
	Perform a throughput test for RSA public key encryption with 50,000 total operations, 1024-bit modulus length, and 1024 descriptors::

		dao-liquid-crypto-perf-test -c 0x3 -- --total-ops 50000 --desc-nb 1024 --optype rsa --asym-op pub-encrypt --rsa-modlen 1024 --ptest throughput

3. **Throughput Test for RSA Decryption**
	Perform a throughput test for RSA private key decryption using the quintuple-based private key, with 25,000 total operations and 1024 descriptors::

		dao-liquid-crypto-perf-test -c 0x3 -- --total-ops 25000 --desc-nb 1024 --optype rsa --asym-op prv-decrypt --rsa-priv-keytype qt --ptest throughput

4. **Latency Test for Passthrough Operation**
	Perform a latency test for the passthrough operation with 128 total ops and burst size is 32::

		dao-liquid-crypto-perf-test -c 0x3 -- --total-ops 128 --optype passthrough --ptest latency --burst-size 32

5. **Latency Test for RSA Encryption**
	Perform a latency test for RSA public key encryption with 256 total operations, 1024-bit modulus length, and burst size is 32::

		dao-liquid-crypto-perf-test -c 0x3 -- --total-ops 256 --optype rsa --asym-op pub-encrypt --rsa-modlen 1024 --ptest latency --burst-size 32

6. **Latency Test for RSA Decryption**
	Perform a latency test for RSA private key decryption using the quintuple-based private key, with 512 total operations and burst size is 32::

		dao-liquid-crypto-perf-test -c 0x3 -- --total-ops 512 --optype rsa --asym-op prv-decrypt --rsa-priv-keytype qt --ptest latency --burst-size 32


Optional Command-Line Options
-----------------------------

The following optional command-line options are available:

* ``-h, --help``

  Display usage information and exit.
