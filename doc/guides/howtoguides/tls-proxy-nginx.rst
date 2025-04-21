..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

*******************************************
Compiling TLS Proxy with NGINX from sources
*******************************************

This section provides step-by-step instructions to compile TLS Proxy with NGINX from sources.

Installing required packages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    apt-get update  -q -y
    apt-get install -y apt-utils build-essential dpkg-dev
    apt-get install -y autoconf automake libtool pkg-config
    apt-get install -y python3-dev python3-minimal python3-pip
    apt-get install -y libmpfr-dev libgmp3-dev libmpc-dev libxml2-dev
    apt-get install -y gcc-14 git wget patch uuid-dev lsb-release
    apt-get install -y zlib1g-dev libpcre3-dev libssl-dev libgd-dev
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100
    update-alternatives --set gcc /usr/bin/gcc-14

Configure and build DPDK-based OpenSSL engine
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    # Clone the DAO repository
    git clone https://github.com/MarvellEmbeddedProcessors/dao.git
    cd dao/

    # Set the base directory and determine the OpenSSL version to use
    BASE_DIR=${PWD}
    OPENSSL_PATCH_VERSION=$(ls patches/nginx/deps/openssl/ | head -n 1)
    OPENSSL_VERSION=${OPENSSL_PATCH_VERSION#v}

    # Download and extract the specified version of OpenSSL
    wget "https://www.openssl.org/source/old/${OPENSSL_VERSION%q}/openssl-${OPENSSL_VERSION}.tar.gz"
    tar -xzf openssl-${OPENSSL_VERSION}.tar.gz
    cd "${PWD}/openssl-${OPENSSL_VERSION}"

    # Apply patches to OpenSSL
    for patch in ${BASE_DIR}/patches/nginx/deps/openssl/${OPENSSL_PATCH_VERSION}/*.patch; do
        patch -p1 < "$patch"
    done

    # Configure and build OpenSSL
    CFLAGS="-Wno-error=implicit-function-declaration" ./Configure --prefix=$PWD/install linux-aarch64
    make
    make install
    mkdir -p "${PWD}/install/usr/lib/cn10k/openssl-${OPENSSL_VERSION}"
    mv "${PWD}/install/lib" "${PWD}/install/usr/lib/cn10k/openssl-${OPENSSL_VERSION}/."
    mv "${PWD}/install/bin" "${PWD}/install/usr/lib/cn10k/openssl-${OPENSSL_VERSION}/."
    mv "${PWD}/install/include" "${PWD}/install/usr/lib/cn10k/openssl-${OPENSSL_VERSION}/."
    mv "${PWD}/install/ssl" "${PWD}/install/usr/lib/cn10k/openssl-${OPENSSL_VERSION}/."
    mv "${PWD}/install/share" "${PWD}/install/usr/lib/cn10k/openssl-${OPENSSL_VERSION}/."

    # Files will be installed in ${BASE_DIR}/openssl-${OPENSSL_VERSION}/install/. Please sync this OpenSSL build to root '/' directory of target.

    cd "${BASE_DIR}"

    # Set the OpenSSL installation directory
    export OPENSSL_INSTALL=$BASE_DIR/openssl-${OPENSSL_VERSION}

    # Determine the DPDK package version and download the appropriate package
    DPDK_BASE_PKG_VERSION=`cat DPDK_VERSION | grep BASE_VERSION | awk -F'=' '{print $2}' | awk -F'.' '{print $1"."$2}'`
    DPDK_PKG_VERSION=`cat DPDK_VERSION | grep RELEASE_VERSION | awk -F'=' '{print $2}'`
    DISTRO=ubuntu-`lsb_release -rs`
    wget "https://github.com/MarvellEmbeddedProcessors/marvell-dpdk/releases/download/dpdk-cn10k-${DPDK_BASE_PKG_VERSION}_${DPDK_PKG_VERSION}-${DISTRO}-${DPDK_PKG_VERSION}/dpdk-${DPDK_BASE_PKG_VERSION}-cn10k_${DPDK_PKG_VERSION}_arm64.deb"

    # Install the DPDK package
    apt-get install -y ./"dpdk-${DPDK_BASE_PKG_VERSION}-cn10k_${DPDK_PKG_VERSION}_arm64.deb"

    # Clone the Marvell OpenSSL engine repository
    git clone "https://github.com/MarvellEmbeddedProcessors/marvell-openssl-engine.git"
    cd "${PWD}/marvell-openssl-engine"

    # Build the DPDK-based OpenSSL engine
    export CFLAGS="-Wno-error=implicit-function-declaration"
    make OTX2=y OSSL_CONF=y DPDK_PC=/usr/lib/aarch64-linux-gnu/pkgconfig/

    # Please sync the dpdk_engine.so at PWD to "/usr/local/lib/engines-1.1/" directory of target.

Configure and build NGINX
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    cd "${BASE_DIR}"
    PCRE_PATCH_VERSION=$(ls patches/nginx/deps/pcre | head -n 1)
    PCRE_VERSION=${PCRE_PATCH_VERSION#v}
    wget "https://sourceforge.net/projects/pcre/files/pcre/${PCRE_VERSION}/pcre-${PCRE_VERSION}.tar.gz/download"
    mv download pcre-${PCRE_VERSION}.tar.gz
    tar xzf pcre-${PCRE_VERSION}.tar.gz
    cd "${PWD}/pcre-${PCRE_VERSION}"
    for patch in ${BASE_DIR}/patches/nginx/deps/pcre/${PCRE_PATCH_VERSION}/*.patch; do
        patch -p1 < "$patch"
    done
    cd ..
    export PCRE_PATH=$BASE_DIR/pcre-${PCRE_VERSION}
    NGINX_PATCH_VERSION=$(ls patches/nginx | tail -n 1)
    NGINX_VERSION=${NGINX_PATCH_VERSION#v}
    echo "NGINX_VERSION=$NGINX_VERSION" >> ${PWD}/artifacts/env
    wget "https://github.com/nginx/nginx/archive/release-${NGINX_VERSION}.tar.gz"
    tar xzf release-${NGINX_VERSION}.tar.gz
    cd "${PWD}/nginx-release-${NGINX_VERSION}"
    for patch in ${BASE_DIR}/patches/nginx/${NGINX_PATCH_VERSION}/*.patch; do
        patch -p1 < "$patch"
    done
    chmod +x configure
    mkdir install
    ./configure --with-pcre=${PCRE_PATH} --with-http_ssl_module --without-http_gzip_module --with-cc-opt="-DNGX_SECURE_MEM -I${OPENSSL_INSTALL}/include -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration" --with-threads  --with-file-aio    --with-ld-opt="-Wl,-rpath=${OPENSSL_INSTALL}/lib -L${OPENSSL_INSTALL}/lib -lssl -lcrypto" --add-dynamic-module=modules/nginx_cpt_module/
    make
    DESTDIR=${PWD}/install/ make install

    # Files will be installed in ${BASE_DIR}/nginx-release-${NGINX_VERSION}/install/. Please sync this Nginx build to root '/' directory of target.