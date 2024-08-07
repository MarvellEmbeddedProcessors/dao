..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

FD.io Vector Packet Processing (VPP)
====================================

1. What is VPP?
---------------
Vector Packet Processing (VPP) is an open-source framework developed under the FD.io (Fast Data project) umbrella. It is designed to offer high-performance packet processing capabilities. VPP uses vector processing techniques to handle multiple packets simultaneously, enhancing throughput and reducing latency. The framework is renowned for its modularity, flexibility, and ability to manage various network functions and protocols.

2. VPP Accelerations
--------------------
VPP offers several accelerations, primarily through vector processing and efficient utilization of CPU cache and memory. Key aspects include:

- **Vector Processing:** Processes packets in batches (vectors) rather than individually, leveraging modern CPU architecture for parallel processing.

- **Cache Efficiency:** Optimizes data structures and algorithms to minimize cache misses, thereby improving performance.

- **Memory Management:** Employs efficient memory allocation and deallocation techniques to reduce overhead.

- **Plugin Architecture:** Supports the integration of various plugins to accommodate different network functions and protocols.

- **IPsec and Crypto Accelerations:** VPP supports both hardware and software accelerations for IPsec, utilizing crypto acceleration hardware when available.

3. Marvell's High-Performance VPP for OCTEON
--------------------------------------------
Marvell's VPP leverages OCTEON's specialized workloads to provide a high-performance VPP stack. The specialized accelerations include:

- **Packet I/O Accelerations:** Enhancements for packet input, output, checksum calculations, and RSS. VPP can be optimized to run on Marvell’s Octeon processors, which are designed for high-performance networking and security applications.

- **Packet Parsing and Classifications:** Programmable parser and classifier that can offload and extend vnet-flow.

- **Crypto Accelerations:** High-performance cryptographic accelerator to offload all cryptographic operations from VPP's crypto layer.

- **Inline IPsec:** Very high-performance inline IPsec implementation that can offload the complete IPsec protocol to OCTEON's cryptographic accelerators.

- **Inline Traffic Management:** Inline traffic shaping and scheduling hardware that can perform inline QoS at line rates.


4. VPP Usage and Integrations
-----------------------------
VPP is used in various high-performance networking applications, including routers, switches, firewalls, and load balancers. Other applications can integrate with VPP through several interfaces:

- **CLI (Command Line Interface):** Provides an interactive shell for configuration and management.

- **VPP API:** Allows external applications to interact with VPP programmatically.

- **VPP Graph Nodes:** Developers can create custom processing nodes within the VPP graph to extend functionality.

- **Memif (Memory Interface):** A high-performance, shared-memory-based packet I/O mechanism for communication between VPP and other applications.

- **VPP's Plugin System:** Enables the addition of new features and protocols without modifying the core code.

- **Sockets Using LD_PRELOAD:** VPP can intercept and accelerate socket operations via the ``LD_PRELOAD`` mechanism, which allows it to replace standard socket library functions with optimized versions.

- **Other Integrations:** VPP can integrate with various other systems and applications, providing APIs and interfaces for seamless communication and interoperability. Examples include:

  - **Kubernetes and Docker:** VPP can be used in containerized environments to provide high-performance networking for microservices.
  - **OpenStack:** VPP can integrate with OpenStack to enhance network functions virtualization (NFV) performance.
  - **gRPC:** VPP can be accessed and managed via gRPC, allowing integration with cloud-native applications.
  - **P4 Runtime:** VPP can interact with P4-programmable devices, providing a flexible data plane programming model.
  - **Linux Control Plane Integration:** VPP can be integrated with the Linux control plane to manage networking and leverage existing Linux networking tools and configurations.
