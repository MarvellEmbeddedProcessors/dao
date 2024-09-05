..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

********************
TLS Proxy with NGINX
********************

Introduction
============

TLS proxy is an intermediate entity/application which sits between a server and client where at least one of them uses TLS for their communication. Based on the type of proxy, it optionally encrypts/decrypts traffic b/w server and client applications. There are different types of TLS proxies

1. TLS termination/Reverse Proxy
   Deployed on the server side. The proxy terminates the TLS connection from the client and sends the decrypted payload to the backend non-TLS application server. Used for adding security, load balancing, caching capabilities to the backend server

2. TLS forwarding Proxy
   Forward proxy is commonly deployed on the client side. Clients are configured to route their traffic via proxy. Proxy decrypts the connection b/w client and itself. Proxy establishes a separate TLS connection with server which is used for communicatio b/w proxy and server.

3. Intercepting Proxy
   Also known as Man-in-the-middle proxy, it intercepts the traffic b/w client and server. It intercepts and inspects the TLS traffic by creating a secure connection with the client and another with the destination server. This type of proxy is typically deployed in the network gateways where TLS traffic inspection is required.

The remainder of the document concentrates mainly on TLS termination proxy.

NGINX Brief
===========
NGINX is an HTTP and reverse proxy server, a mail proxy server, a generic TCP/UDP proxy server. It is widely used both as web/proxy server throughout the internet. The rest of the document uses NGINX to configure and use it as a TLS termination proxy.

NGINX as TLS termination proxy
==============================

Usage/deployment Model
----------------------

This section discusses on the steps to deploy NGINX as a TLS termination proxy.

NGINX Architecture Diagram
--------------------------

1. NGINX as TLS termination proxy with inbuilt web server

   .. figure:: ./img/nginx-https-server.png

2. NGINX as TLS termination proxy with separate backend web/application server

   .. figure:: ./img/nginx-tls-termination.png

NGINX acceleration on OCTEON
----------------------------

NGINX application provided in this solution is modified to add following features

1. Changes required to leverage asynchronous mode in OpenSSL
2. Changes required to leverage engine framework in OpenSSL for crypto acceleration
3. Changes required to use dpdk engine via OpenSSL engine framework
4. Changes required to leverage pipelining support in OpenSSL

The modified NGINX has better performance as it offloads crypto operations such as RSA and ECDSA
sign/verify operations to CPT via dpdk engine interface. The asynchronous feature allows NGINX not to
waste CPU cycles while crypto operations are offloaded to CPT via dpdk engine framework. The pipelining
feature also allows NGINX to utlizie pipeline support exposed by openssl for burst submission of
crypto operations to CPT. This allows the NGINX application to amortize the crypto operation submission to
CPT over a burst of packets. It also allows for multiple submissions when the user data is broken into
multiple TLS records.

Steps to Build
==============

Getting Sources
---------------

Ubuntu Debian package
^^^^^^^^^^^^^^^^^^^^^

Before downloading the NGINX package, make sure ubuntu repository is setup properly
`Setting up Ubuntu repo for DAO <https://marvellembeddedprocessors.github.io/dao/guides/gsg/install.html#update-ubuntu-repository-to-download-dao-packages>`_

Installing the NGINX package
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    ~# apt-get install nginx-1.22.0-cnxk-devel

Environment Setup
=================

Enabling CPT device
-------------------

.. code-block:: console

    ~# echo 1 > /sys/bus/pci/devices/0002\:20\:00.0/sriov_numvfs
    ~# dpdk-devbind.py -b vfio-pci 0002:20:00.1

NGINX configuration
-------------------

.. code-block:: console

    ~# cat /conf/nginx.conf

NGINX as HTTPS Server
^^^^^^^^^^^^^^^^^^^^^

Following example async_nginx.conf allows user to run nginx with inbuilt HTTP server

.. code-block:: text

  user  root root;
  daemon off;
  worker_processes 1;

  error_log  logs/error.log;
  #error_log  logs/error.log  notice;
  #error_log  logs/error.log  info;

  load_module modules/ngx_ssl_engine_cpt_module.so;

  ssl_engine {
      use_engine dpdk_engine;
      default_algorithms ALL;
      cpt_engine {
          cpt_poll_mode heuristic;
          cpt_offload_mode async;
          #cpt_notify_mode poll;
          #cpt_heuristic_poll_asym_threshold 24;
      }
  }

  events {
      use epoll;
      worker_connections  1024;
      multi_accept on;
      accept_mutex off;
  }

  http {
        keepalive_timeout 300s;
        connection_pool_size 1024;
        keepalive_requests 1000000;
        access_log off;
        server {
                listen 443 ssl default_server;
                ssl_certificate /etc/nginx/certs/server.crt.pem;
                ssl_certificate_key /etc/nginx/certs/server.key.pem;
                ssl_client_certificate /etc/nginx/certs/rootca.crt.pem;
                ssl_asynch on;
                ssl_max_pipelines 8;

                root /var/www/html;

                index index.html index.htm index.nginx-debian.html;

                server_name _;

                location / {
                        try_files $uri $uri/ =404;
                }
        }

        # Port  443 - SSL
        #include /etc/nginx/sites-enabled/*;
        # Port 80 - TCP
        #include /etc/nginx/sites-available/*;
  }

NGINX as TLS Forwarder
^^^^^^^^^^^^^^^^^^^^^^

Following example tls-proxy-forwarding-async_nginx.conf allows users to configure NGINX to work as HTTPS forwarding proxy where both connections from SSL client to NGINX and NGINX to backend server are secured using SSL:

.. code-block:: text

  user  root root;
  daemon off;
  worker_processes 1;

  error_log  logs/error.log;

  load_module modules/ngx_ssl_engine_cpt_module.so;

  ssl_engine {
      use_engine dpdk_engine;
      default_algorithms ALL;
      cpt_engine {
          cpt_poll_mode heuristic;
          cpt_offload_mode async;
      }
  }

  events {
      use epoll;
      worker_connections  65536;
      multi_accept on;
      accept_mutex off;
  }

  http {
      keepalive_timeout 300s;
      connection_pool_size 1024;
      keepalive_requests 1000000;
      access_log off;
      server {
            listen 443 ssl default_server;
            ssl_certificate /etc/nginx/certs/server.crt.pem;
            ssl_certificate_key /etc/nginx/certs/server.key.pem;
            ssl_client_certificate /etc/nginx/certs/rootca.crt.pem;
            ssl_asynch on;
            ssl_max_pipelines 8;
            root /var/www/html;
            index index.html index.htm index.nginx-debian.html;
            server_name _;
            location / {
                # where 2.0.0.2:443 is the backend HTTPS server:port
                proxy_pass https://2.0.0.2/;
            }
      }

  }

NGINX as TLS Initiator
^^^^^^^^^^^^^^^^^^^^^^

Following example backend-https-async_nginx.conf users to configure NGINX to work as a SSL proxy client to HTTP clients and communicate with HTTPS servers using SSL:

.. code-block:: text

  user  root root;
  daemon off;
  worker_processes 1;

  error_log  logs/error.log;

  load_module modules/ngx_ssl_engine_cpt_module.so;

  ssl_engine {
      use_engine dpdk_engine;
      default_algorithms ALL;
      cpt_engine {
          cpt_poll_mode heuristic;
          cpt_offload_mode async;
      }
  }

  events {
      use epoll;
      worker_connections  65536;
      multi_accept on;
      accept_mutex off;
  }

  http {
      keepalive_timeout 300s;
      connection_pool_size 1024;
      keepalive_requests 1000000;
      access_log off;
      server {
            # the Client connects to 8000 port on NGINX
            listen 8000;
            ssl_certificate /etc/nginx/certs/server.crt.pem;
            ssl_certificate_key /etc/nginx/certs/server.key.pem;
            ssl_max_pipelines 8;
            root /var/www/html;
            index index.html index.htm index.nginx-debian.html;
            server_name _;
            location / {
                # where 2.0.0.2:443 is the backend HTTPS server:port
                proxy_pass https://2.0.0.2/;
            }
      }

  }


OpenSSL configuration
---------------------

.. code-block:: console

    ~# cat /opt/openssl.cnf

OpenSSL example conf
^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

  #
  # OpenSSL dpdk_engine Configuration File
  #

  # This definition stops the following lines choking if HOME isn't
  # defined.
  HOME                    = .

  openssl_conf = openssl_init

  [ openssl_init ]
  engines = engine_section

  [ eal_params_section ]
  eal_params_common = "E_DPDKCPT --socket-mem=500  -d librte_mempool_ring.so"
  eal_params_cptpf_dbdf = "0002:20:00.1"

  [ engine_section ]
  dpdk_engine = dpdkcpt_engine_section

  [ dpdkcpt_engine_section ]
  dynamic_path = /opt5/openssl-engine-dpdk/dpdk_engine.so
  eal_params = $eal_params_section::eal_params_common

  # Append process id to dpdk file prefix, turn on to avoid sharing hugepages/VF with other processes
  # If setting to no, manually add --file-prefix <name> to eal_params
  eal_pid_in_fileprefix = yes

  # Append -l <sched_getcpu()> to eal_params
  # If setting to no, manually add -l <lcore list> to eal_params
  eal_core_by_cpu = yes

  # Whitelist CPT VF device
  # Choose CPT VF automatically based on core number
  # replaces dd.f (device and function) in below PCI ID based on sched_getcpu
  eal_cptvf_by_cpu = $eal_params_section::eal_params_cptpf_dbdf

  cptvf_queues = {{0, 0}}
  engine_alg_support = ALL
  # Crypto device to use
  # Use openssl dpdk crypto PMD
  # crypto_driver = "crypto_openssl"
  # Use crypto_cn10k crypto PMD on cn10k
  #crypto_driver = "crypto_cn10k"
  # Use crypto_cn9k crypto PMD on cn9k
  crypto_driver = "crypto_cn9k"
  engine_log_level = ENG_LOG_INFO
  init=0

Launching the application
=========================

Running the Proxy Application
-----------------------------

.. code-block:: console

    ~# OPENSSL_CONF_MULTI=<path-to-conffile>/openssl.cnf <path-to-nginx-bin>/sbin/nginx -c <path-to-conffile>/async_nginx.conf

NOTE: Path to NGINX application = /usr/local/nginx/

Functional Testing of the Proxy
-------------------------------

.. code-block:: console

    ~# ab -i -c1 -n1 -f TLS1.2 -Z AES128-GCM-SHA256 https://<nginx-dut-ip>/test/<FILE_SIZE>.html

NOTE: A file <FILE_SIZE>.html (eg: 4MB.html) has to be created in the directory where nginx application is executed.

Performance Testing of the Proxy
--------------------------------

Kernel Parameters Tuning for best performance
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Following kernel parameters should be set for load testing of nginx as well as to achieve optimal performance from linux kernel tcp stack.

.. code-block:: console

    ~# sysctl net.core.rmem_max=33554432
    ~# sysctl net.core.wmem_max=33554432
    ~# sysctl net.ipv4.tcp_rmem="4096 87380 33554432"
    ~# sysctl net.ipv4.tcp_wmem="4096 65536 33554432"
    ~# sysctl net.ipv4.tcp_window_scaling
    ~# sysctl net.ipv4.tcp_timestamps
    ~# sysctl net.ipv4.tcp_sack
    ~# ifconfig enP2p5s0 txqueuelen 5000
    ~# echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout
    ~# echo 30 > /proc/sys/net/ipv4/tcp_keepalive_intvl
    ~# echo 5 > /proc/sys/net/ipv4/tcp_keepalive_probes
    ~# echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle
    ~# echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse
    ~# sysctl net.ipv4.tcp_tw_recycle=1
    ~# sysctl net.ipv4.tcp_no_metrics_save=1
    ~# sysctl net.core.netdev_max_backlog=30000
    ~# sysctl net.ipv4.tcp_congestion_control=cubic
    ~# echo 5 > /proc/sys/net/ipv4/tcp_fin_timeout

Performance measurement using ab client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The apache benchmark utility (ab) can be used to benchmark nginx

.. code-block:: console

    ~# ab -i -c64 -n10000 -f TLS1.2 -Z AES128-GCM-SHA256 https://<nginx-dut-ip>/test/<FILE_SIZE>.html

Performance using h2load client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

    ~# h2load  -n 10000 -c 64 --cipher=AES128-GCM-SHA256,2048,256 https://<nginx-dut-ip>/test/<FILE_SIZE>.html

Application running demo
^^^^^^^^^^^^^^^^^^^^^^^^

.. raw:: html
  :file: ../_static/demo/nginx.html