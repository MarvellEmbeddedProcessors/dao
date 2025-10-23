..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

********************************************
NGINX TLS Offload Using OCTEON Crypto Engine
********************************************

Executive Summary
=================
Modern applications rely on HTTPS for secure communication, but software-based TLS processing can overwhelm CPUs and limit scalability.
As encrypted traffic volumes grow, cloud and enterprise providers need solutions that deliver strong security *without* compromising
performance or energy efficiency.

**Marvell DAO's NGINX TLS Offload Solution** uses the **OCTEON DPU's Crypto (CPT) Engine** to accelerate cryptographic operations
directly in hardware. Integrated seamlessly through the **Marvell OpenSSL Engine**, it enables NGINX to offload TLS handshakes and
encryption from general-purpose CPU cores to dedicated hardware.

The result:

- Up to **5.7** higher TLS handshake rate (CPS).
- Up to **45 Gbps (50G Line rate)** throughput.
- **65%** lower CPU utilization.
- **23W** peak power consumption.

This makes it ideal for **Content Delivery Networks (CDN), Cloud Load Balancer, and Edge TLS Gateway** deployments that demand both
performance and efficiency.


Solution Overview
=================

**NGINX** is the backbone of modern web, API, and proxy workloads. Under heavy TLS encryption, CPU resources quickly become a limiting factor.

**Marvell DAO** integrates NGINX with the **CPT Engine** on **OCTEON DPUs** to deliver high-speed hardware acceleration for cryptographic
functions such as RSA, AES-GCM, and SHA. The integration is achieved through **Marvell’s OpenSSL Engine**, providing a *drop-in replacement*
for software based crypto with no application changes required.

   .. figure:: ./img/async-nginx-cpt.png

Key Benefits
^^^^^^^^^^^^

- Hardware-accelerated TLS encryption and handshake processing
- Transparent integration using the OpenSSL engine
- Frees CPU cores for application and networking logic
- Scales efficiently up to 45 Gbps (50G line rate) at only 23 W power

Architecture & Design
=====================
The DAO framework provides a transparent acceleration path that bridges NGINX’s TLS stack with Marvell’s CPT hardware engine on the OCTEON DPU
through the Marvell's OpenSSL Engine. When NGINX processes TLS traffic, cryptographic operations are initiated via OpenSSL and seamlessly
intercepted by the Marvell's OpenSSL Engine. Eligible crypto operations, such as AES-GCM encryption, RSA signing, or SHA hashing are offloaded
to the CPT hardware for execution, while non-eligible requests continue in software without disruption.

The **Marvell's OpenSSL Engine** manages the offload lifecycle, including buffer management, request dispatch, and result completion, ensuring
low-latency and high-throughput operation. Once the CPT engine completes the operation, results are returned transparently to OpenSSL and NGINX,
maintaining full protocol compliance.


Workflow
^^^^^^^^
Below block diagram illustrates the NGINX configured as an HTTPS server with hardware offload.

   .. figure:: ./img/async-nginx-setup.png

#. Client initiates TLS traffic to HTTPS (NGINX) server.
#. After TCP connection establishment with the NGINX, client initiates TLS operations(handshake, SSL read & write) using OpenSSL.
#. Kernel  stack on Octeon DPU handles the TCP connection and hands TLS operations to NGINX.
#. NGINX calls OpenSSL APIs to perform TLS operations.
#. Marvell OpenSSL Engine detects eligible TLS (crypto) operations for offload.
#. Marvell OpenSSL Engine creates asynchronous jobs and submits to CPT engine via DPU for execution.
#. CPT engine performs crypto operations at line rate.
#. Engine APIs in NGINX application polls for the completed crypto operations from CPT.
#. Engine resums the asynchronous job once the crypto operation results are available from CPT.
#. Marvell OpenSSL Engine delivers the processed/finished jobs back to NGINX.
#. NGINX completes the TLS operation and responds back to client.

This design achieves high throughput, low latency, and consistent performance with minimal system overhead.


Performance Highlights
======================
Below graph shows performance results for connections per second (CPS) and throughput (Gbps)
tests with different numbers of NGINX workers (ARMv8 cores on DPU). CPS test measures how
efficiently the system can perform TLS handshakes and establish secure connections using a
small 100B file size.

   .. figure:: ./img/async-nginx-cps.png

And the throughput test was conducted with 1GB file size. The small payload size minimizes data transfer
overhead, enabling an accurate evaluation of TLS connection handling, CPU utilization, and the crypto
offload efficiency provided by Marvell's OpenSSL Engine.

   .. figure:: ./img/async-nginx-gbps.png

From the results, the NGINX HTTPS server reaches peak performance of CPT between 8-9 Armv8
cores, highlighting its scalability and efficiency for TLS workloads with crypto offload.
And the throughput results indicate that DPU can reach up to 45 Gbps with 12 workers.

.. note::
 The peak performance of the CPT engine for RSA 2Kb signature operations is 20K sign/sec.

+-------------------------+-------------------+----------------------+-----------------+
| **Metric**              | **Software Only** | **With CPT Offload** | **Improvement** |
+-------------------------+-------------------+----------------------+-----------------+
| TLS Handshake Rate (CPS)| 1.0×              | **3.9×**             | +290%           |
| at CPT Peak performance |                   |                      |                 |
+-------------------------+-------------------+----------------------+-----------------+
| CPU Utilization for     | 24 Cores          | 9-12 Core            | 40-50%          |
| Peak (20K CPS & 45 Gbps)|                   |                      |                 |
+-------------------------+-------------------+----------------------+-----------------+
| Power Draw at Peak      | 60 W              | **23 W**             | 40-50%          |
+-------------------------+-------------------+----------------------+-----------------+

Performance Insights
^^^^^^^^^^^^^^^^^^^^

- CPT engine peak performance achieved with 8–9 ARMv8 cores
- Linear throughput scaling up to 12 workers
- Sustained efficiency across TLS workloads

DAO Components
==============

#. `Marvell NGINX <https://github.com/MarvellEmbeddedProcessors/dao/tree/dao-devel/patches/nginx>`_
#. `Marvell DPDK <https://github.com/MarvellEmbeddedProcessors/marvell-dpdk>`_
#. `Marvell OpenSSL Engine <https://github.com/MarvellEmbeddedProcessors/marvell-openssl-engine>`_


Use Cases
=========
#. **Cloud TLS Termination** — Accelerate large-scale HTTPS handshakes for web services.
#. **CDN Edge Offload** — Reduce latency and power usage for distributed secure delivery.
#. **Enterprise Reverse Proxy** — Free up host CPU resources while maintaining strong encryption.
#. **Data Center TLS Gateways** — Enable secure, high-bandwidth east–west traffic.


Key Takeaways
=============

#. Up to **3.9×** higher CPS and **65% lower CPU usage** achieved with DAO-based TLS offload.
#. **45 Gbps throughput** at **only 23 W**, enabling secure, efficient HTTPS at scale.
#. **Drop-in integration** through OpenSSL with no code modifications.
#. Fully supported within **Marvell DAO Release 25.01**, ready for production deployments.

How To Use
==========
Refer
`DAO page <https://marvellembeddedprocessors.github.io/dao/guides/dao-devel/applications/tls-proxy-nginx.html>`_
to try NGINX solution in different modes.

**Contact**
==============
`DAO <mailto:dao@marvell.com>`_

