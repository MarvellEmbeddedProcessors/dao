..  SPDX-License-Identifier: Marvell-MIT

====================
DAO Crypto Agent App
====================

Overview
--------
The DAO Crypto Agent acts as a daemon service on the Liquid Crypto Card. It
receives cryptographic requests from the host, submits them to the CPT
hardware, collects completions, and returns results to the host.
Its primary goal is to provide a low‑latency, high throughput path between
host software and CPT hardware resources.

Optionally, when built and started with compress support, the agent also accepts
DEFLATE compress/decompress requests from the host, schedules them on compression/
decompression (ZIP) device, and returns results over the same Ethernet transport
as CPT operations.

Core responsibilities:

* Initialize platform (DPDK EAL, memory pools, queues, ports)
* Manage cryptodev queue pairs and session resources
* Schedule and enqueue incoming crypto operations to CPT
* Dequeue CPT completions and format responses
* Schedule and enqueue compress/decompress operations to ZIP (optional)
* Dequeue ZIP completions and format responses
* Expose lightweight control & info operations (init, info, stats, shutdown)

While a gRPC interface is available for lifecycle and informational queries,
the data path focus remains efficient request/response dispatch.

Architecture Summary
--------------------
* Control Plane: thin gRPC handlers translate host control requests into local
	setup / query functions.
* Data Plane: per-lcore workers pull host-submitted operations, enqueue to CPT,
	and dequeue completions (poll mode) for return. Optionally when compress
	device is enabled, enqueue compress/decompress operations to ZIP and
	dequeue completions (poll mode) for return.
* Hardware Interface: CPT cryptodev queues sized per configuration; session
	objects cached for reuse. Compression devices use DPDK compressdev PMD
	queue pairs to perform compression and decompression using the DEFLATE
	algorithm.
* Synchronization: lockless fast path; RCU / QSBR (where applicable) for safe
	teardown of shared objects.

Lifecycle
---------
1. Startup (card boot): service binary is launched via init scripts.
2. Host issues ``card_init`` (optionally with ``enable-compress-dev``): resources
	 (mbuf pools, cryptodev QPs, ethernet devices if required, and compress
	 devices if enabled) are allocated and configured.
3. Operational: workers process host requests and generate statistics.
4. Info/Stats: host may call ``card_info`` / stats RPCs at any time.
5. Teardown: host requests shutdown; workers quiesce, resources freed.

Host Interaction
----------------
Host-side card manager triggers initialization. Host side DAO application calls
liquid_crypto library APIs to submit crypto operations expecting responses once
CPT completes processing.

Validation
----------
To verify correct operation, run ``liquid-crypto-autotest`` on the host after
following the Host Setup instructions in the platform guide. Successful test
completion confirms enqueue/dequeue and result paths are functioning.

Build & Run
-----------
The agent is built as part of the standard project build and launched
automatically at card boot via init scripts. Manual invocation is typically
unnecessary. Operators interact with the crypto-agent application through the
host-side card manager interface.

References
----------
* :doc:`Liquid Crypto Platform Guide <../platform/liquid_crypto>` – host setup,
  autotest usage, and platform prerequisites.
