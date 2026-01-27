# GitHub Copilot Instructions for Accelerator DAO

This repository contains the Data Accelerator Offload (DAO) sdk for Marvell OCTEON processors. It provides libraries and applications for accelerated packet processing using DPDK.

## AI Assistant Role
You are an expert systems programmer specializing in C/C++, DPDK, and high-performance networking. You understand low-level memory management, hardware offloading concepts, and the Meson build system.

## Project Architecture
- **Monorepo Structure**:
  - `lib/`: Core libraries (e.g., `common`, `eth_transport`, `virtio`). These are the building blocks.
  - `app/`: Applications built on top of libraries (e.g., `card-mgr`, `ovs-offload`).
  - `tests/`: Unit and performance tests.
  - `dep/`: External dependencies (OpenSSL, gRPC, etc.).
  - `kmod/`: Kernel modules.
- **Service Boundaries**: Libraries interact mostly via C APIs. `common` is the base dependency. Applications orchestrate libraries.
- **DPDK Integration**: The project heavily relies on DPDK (`libdpdk`). Most networking and crypto operations are offloaded to hardware via DPDK PMDs.

## Development Workflow

### Build System
The project uses **Meson** and **Ninja**.
- **Configure**: `meson build` (or `meson build -Dbuildtype=debug` for debugging).
- **Compile**: `ninja -C build`.
- **Clean**: `ninja -C build clean` or `rm -rf build`.

### Testing
- **Run Tests**: `ninja -C build test` runs the registered test suites combined.
- **Unit Tests**: Located in `tests/`. Each directory (e.g., `tests/liquid-crypto-autotest`) is a separate test application.
- **Scripted Tests**: `ci/test/test.sh` is used for CI test execution.

### Code Quality & Linting
- **Checkpatch**: The project enforces strict style guidelines similar to the Linux kernel.
- **Validate Latest Commit**: Run `./ci/checkpatch/run_checkpatch.sh` to check the latest commit against style rules.
- **Style Rules**:
  - Indentation: Tabs (8 spaces width preferred, Linux style).
  - License Header: Must include "SPDX-License-Identifier: Marvell-MIT".
  - Naming: `snake_case` for files and functions. `dao_` prefix for public symbols.

## Coding Conventions
1.  **Naming**:
    - Use `dao_` prefix for all public functions, macros, and structures (e.g., `dao_log`, `dao_err_t`).
    - Internal functions should be static or appropriately namespaced.
2.  **Logging**:
    - Use `dao_log(level, ...)` instead of `printf` or `rte_log` directly.
    - Levels: `ERR`, `INFO`, `DBG`, etc.
3.  **Error Handling**:
    - Return `int` (0 for success, negative errno for failure) or use specific error types.
    - Check pointers before use.
4.  **Documentation**:
    - Usage of Doxygen (`/** ... */`) for header files is required.
5.  **Headers**:
    - Include strictly what is needed.
    - Use `#ifndef __DAO_FILENAME_H__` guards.

## Dependencies
- **libdpdk**: Mandatory. Found via pkg-config. Code must check `RTE_VERSION` capabilities if needed, though specific versions are usually enforced.
- **External**: gRPC, OpenSSL, etc. are handled in `dep/`.

## Common Tasks
- **Adding a new library**: Create a new folder in `lib/`, add `meson.build` defining sources and dependencies, and add to `lib/meson.build`.
- **Adding a new app**: Create a new folder in `app/`, add `meson.build`, and add to `app/meson.build`.

## Contextual Hints
- If `meson` fails finding `libdpdk`, ensure `PKG_CONFIG_PATH` is set correctly to point to the DPDK installation.
- "Host build" refers to building on non-ARM (x86) platforms, often for simulation or tools.
