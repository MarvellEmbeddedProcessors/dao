..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

***************************************************************
NGINX TLS Offload Using OCTEON Crypto Engine With VPP Hoststack
***************************************************************

Executive Summary
=================
Modern applications rely on HTTPS for secure communication, but software-based TLS processing can overwhelm CPUs and limit scalability. As encrypted traffic
volumes grow, cloud and enterprise providers need solutions that deliver strong security *without* compromising performance and energy efficiency.

**Marvell DAO's NGINX Acceleration Solution** uses VPP's hoststack for efficient TCP/IP processing and **OCTEON DPU's Crypto (CPT) Engine** to accelerate
TLS crypto operations directly on crypto hardware. Integrated seamlessly through the VPP Hoststack (using LD_PRELOAD) and **Marvell OpenSSL Engine**,
enables NGINX to offload TLS operations (handshakes, encryption and decryption) from general-purpose CPU cores to dedicated CPT engine. By leveraging the
VPP Host Stack and Marvell's OpenSSL Engine this solution delivers scalable HTTPS performance while significantly reducing CPU overhead.

**Marvell DAO NGINX Acceleration Solution** demonstrates consistently high connection rates (CPS)s and throughput across all supported deployment modes.
This makes the solution well-suited for TLS intensive high-connection-rate workloads such as NGINX reverse proxies, load balancers, large scale cloud, CDN
and edge TLS gateways where both high concurrency and sustained throughputs are critical.

Solution Overview
=================

**NGINX** is the backbone of modern web, API, and proxy workloads. Under heavy TLS load, CPU resources quickly become a limiting factor.

Marvell DAO integrates NGINX’s TLS stack with Marvell’s VPP Host Stack with OpenSSL Engine which leverages the CPT Engine on OCTEON DPUs to deliver high-speed
hardware acceleration for cryptographic functions such as RSA, AES-GCM, and SHA. The integration is enabled through Marvell’s OpenSSL Engine, while the VPP
Host Stack provides a flexible, high-performance userspace networking framework for NGINX deployments, ensuring efficient packet processing and seamless TLS
offload.

   .. figure:: ./img/vpp-nginx-config-modes.png

The entire packet processing pipeline, from ingress to application handling and response egress, remains in userspace. VPP manages the networking flow,
while cryptographic tasks are offloaded concurrently to hardware accelerators, achieving maximum efficiency by avoiding kernel involvement and minimizing
latency.

Key Benefits
^^^^^^^^^^^^
- Enhanced by Marvell’s CPT hardware offload, delivering high-speed, energy-efficient TLS processing.
- Operates entirely in userspace, enabling complete bypass of the Linux kernel networking stack to minimize latency and maximize throughput.

Architecture & Design
=====================
The DAO framework provides a transparent acceleration path that bridges NGINX’s TLS stack with Marvell’s VPP Host Stack and CPT hardware engine on the
**OCTEON DPU** through Marvell’s OpenSSL Engine. When NGINX processes HTTPS traffic, the VPP Host Stack replaces the traditional kernel TCP/IP stack to
deliver high-performance, user-space networking, while cryptographic operations are initiated via OpenSSL in NGINX are seamlessly intercepted by Marvell’s
OpenSSL Engine. Eligible TLS crypto operations, such as AES-GCM encryption, RSA signing, or SHA hashing, are offloaded to the CPT hardware for execution,
while non-eligible requests continue in software without disruption.

VPP Host Stack replaces the traditional kernel TCP/IP stack with a high-performance, user-space networking framework optimized for multi-core DPUs.
It provides complete session management for TCP, UDP, and QUIC connections, enabling applications like NGINX to establish, maintain, and terminate sessions
entirely in user space with minimal latency. In this architecture, the VPP Host Stack handles all socket-level operations—including connection setup, teardown,
flow control, and retransmission using LD_PRELOAD. Standard POSIX socket APIs (e.g., socket(), connect(), send(), recv()) are transparently redirected to VPP’s
session layer, allowing unmodified applications to benefit from its accelerated data path.

The Marvell OpenSSL Engine manages the offload lifecycle, including buffer management, request dispatch, and result completion, ensuring low-latency and
high-throughput operation. Once the CPT engine completes the operation, results are returned transparently to OpenSSL, NGINX and the VPP Host Stack,
maintaining full protocol compliance and maximizing overall system efficiency.


Workflow
^^^^^^^^
Below block diagram illustrates the flow between client, VPP hoststack and NGINX with hardware offload in different configuration modes.

   .. figure:: ./img/async-nginx-setup.png

#. Client initiates TLS traffic to the NGINX server.
#. The VPP Host Stack on the OCTEON DPU handles all TCP/IP processing in user space, replacing the traditional kernel networking stack, and forwards the TLS payloads to NGINX.
#. After establishing a TCP connection with NGINX, the client begins TLS operations (handshake, SSL read and write) using OpenSSL.
#. NGINX invokes OpenSSL APIs to perform TLS handshake and data encryption/decryption.
#. The Marvell OpenSSL Engine identifies eligible TLS (crypto) operations for hardware offload.
#. The engine creates asynchronous crypto jobs and submits them to the CPT hardware engine on the DPU.
#. The CPT engine performs cryptographic operations (e.g., AES-GCM, RSA, SHA) at line rate.
#. The engine’s asynchronous interface within NGINX polls for completed crypto operations from the CPT engine.
#. Once results are available, the engine resumes the corresponding asynchronous jobs.
#. The Marvell OpenSSL Engine returns the processed crypto results back to NGINX transparently.
#. NGINX completes the TLS operations and responds to the client via the VPP Host Stack, ensuring low-latency and high-throughput HTTPS communication.
#. If NGINX is configured in reverse proxy mode, it initiates new TLS connection towards the backend server.
#. If NGINX is configured in forward proxy mode, it forwards the same TLS connection towards the backend server.

Performance Highlights
======================

NGINX as HTTPS Server With VPP Host Stack
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The following diagram depicts the end-to-end flow from the client to the
NGINX HTTPS server when NGINX operates in HTTPS server mode.

   .. figure:: ./img/vpp-nginx-serv.png

The following graph illustrates the performance of the nginx https server
across various combinations of VPP and NGINX worker configurations.

   .. figure:: ./img/vpp-nginx-server-perf.png

NGINX as Reverse Proxy With VPP Host Stack
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The following diagram depicts the end-to-end flow from the client to the
backend HTTPS server when NGINX operates in Reverse (termination) proxy mode.

For each TLS connection, NGINX opens a new TLS connection towards the backend server.

   .. figure:: ./img/vpp-nginx-rev-pxoy.png

The following graph illustrates the performance of the reverse proxy across
various combinations of VPP and NGINX worker configurations.

   .. figure:: ./img/vpp-nginx-rproxy-perf.png

NGINX as Forward Proxy With VPP Host Stack
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The following diagram depicts the end-to-end flow from the client to the
backend HTTPS server when NGINX operates in Forward proxy mode.

For each TLS connection, NGINX forwards same TLS connection towards the backend server.

   .. figure:: ./img/vpp-nginx-fwd-pxoy.png

The following graph illustrates the performance of the forward proxy across
various combinations of VPP and NGINX worker configurations.

   .. figure:: ./img/vpp-nginx-fproxy-perf.png

Performance Summary
""""""""""""""""""""
Below is summary of different configuration modes with 8-NGINX and 8-VPP workers configuration.

  +-------------------------------+-----------------------------+-----------+
  | **NGINX Configuration Mode**  | **Max Throughput (Gbps)**   | **CPS**   |
  +-------------------------------+-----------------------------+-----------+
  | HTTPS Server                  |  45 Gbps                    | 5.5K      |
  +-------------------------------+-----------------------------+-----------+
  | Forward Proxy                 |  34 Gbps                    | 5.8K      |
  +-------------------------------+-----------------------------+-----------+
  | Reverse Proxy                 |  32 Gbps                    | 6K        |
  +-------------------------------+-----------------------------+-----------+

DAO Components
==============

#. `Marvell VPP <https://github.com/MarvellEmbeddedProcessors/vpp>`_
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
#. The performance evaluation of the Marvell DAO NGINX Acceleration Solution demonstrates strong scalability and efficiency across multiple deployment modes.
#. The solution achieves high throughput and connection rates across HTTPS server, forward proxy, and reverse proxy configurations.
#. HTTPS server mode delivers the highest overall throughput, showcasing the efficiency of TLS offload through the CPT Engine.
#. Forward and reverse proxy modes maintain strong CPS performance, highlighting balanced scalability for bidirectional traffic flows.
#. The combination of the VPP Host Stack and CPT hardware acceleration enables near line-rate HTTPS performance with significantly reduced CPU utilization.

How To Use
==========
Refer
`DAO page <https://marvellembeddedprocessors.github.io/dao/guides/dao-devel/applications/tls-proxy-nginx.html>`_
to try NGINX solution in different modes.

**Contact**
==============
`DAO <mailto:dao@marvell.com>`_
