..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2025 Marvell.

*********************
Snort with VectorScan
*********************

What is Snort?
==============
Snort is a open-source Intrusion Prevention System (IPS). It utilizes a series of rules
to define malicious network activity, identifying packets that match these rules and
generating alerts for users.

What is VectorScan?
===================
VectorScan is a high-performance regular expression matching library. It is a portable
fork of Intel's Hyperscan, designed to run on multiple platforms.

Accelerations
==============
- **Optimized for ARM:** VectorScan has been optimized to accelerate regular
  expression parsing on ARM platforms, particularly using ARM's NEON and SVE2 vector engines.

- **Integration with Applications:** VectorScan can be integrated with applications
  like Snort 3 for deep packet inspection (DPI), leveraging ARM's vector processing
  to enhance performance.

Installing Snort
================
Ubuntu Debian package
---------------------
Before downloading the Snort package, make sure ubuntu repository is setup properly
`Setting up Ubuntu repo for DAO <https://marvellembeddedprocessors.github.io/dao/guides/gsg/install.html#update-ubuntu-repository-to-download-dao-packages>`_

Install the Snort package and verify
------------------------------------

- Release version

.. code-block:: console

    ~# apt-get install snort-3-cn10k
    ~# /usr/local/bin/snort -V

- `steps to install the Development version <https://marvellembeddedprocessors.github.io/dao/guides/gsg/install.html#development-version>`_

VectorScan Benchmarking
=======================
Vectorscan version 4.4 and later include a standard benchmarking tool, hsbench,
designed to provide an easy way to measure key performance metrics for a particular
set of patterns and a corpus of data to be scanned.

Pattern Sets
------------
Three sample pattern sets examined here are:

1. snort_literals: This is a set of 3,316 literal patterns extracted from the
   sample ruleset included with the Snort* 3 network intrusion detection system,
   available at https://github.com/snortadmin/snort3.

2. snort_pcres: This is a set of 847 regular expressions that were also
   extracted from the sample ruleset includes with Snort 3, taken from rules
   targeted at HTTP traffic. It is important to note that these are just the
   patterns extracted from the rules’ “pcre:” options, and that scanning for
   them in a single pattern set with Hyperscan is not semantically equivalent
   to scanning for these rules within Snort.

3. teakettle_2500: This is a set of 2,500 synthetic pattern generated with a
   script that produces regular expressions of limited complexity. These are
   composed of dictionary words separated by character class repeats and alternations.

Performance measurements
-------------------------
As an example, the following sample measurements were collected using hsbench tool
on CN106XX. In these commands, we use the Linux taskset utility to pin the process
to the first core on the system.

1. Snort literals against HTTP traffic, block mode.
   $ taskset 1 hsbench -e pcre/snort_literals -c corpora/alexa200.db -N

2. Snort PCREs against HTTP traffic, block mode.
   $ taskset 1 hsbench -e pcre/snort_pcres -c corpora/alexa200.db -N

3. Teakettle synthetic patterns against Gutenberg text, streaming mode.
   $ taskset 1 hsbench -e pcre/teakettle_2500 -c corpora/gutenberg.db

+----------------+-----------------+------------------+----------------+----------------+------------------+
| **PatternSet** | **Scan Corpus** | **Num Patterns** | **Matches/KB** | **Blocks/Sec** | **Megabits/Sec** |
|                |                 |                  |                |                |                  |
+----------------+-----------------+------------------+----------------+----------------+------------------+
| Snort Literals | HTTP Traffic    | 3,116            | 3.686          | 303,214        | 3,282            |
|                |                 |                  |                |                |                  |
+----------------+-----------------+------------------+----------------+----------------+------------------+
| Snort PCREs    | HTTP Traffic    | 847              | 8.804          | 96,664         | 1,046            |
|          	 |                 |                  |                |                |                  |
+----------------+-----------------+------------------+----------------+----------------+------------------+
| TeaKettle 2500 | Gutenberg Text  | 2,500            | 0.576          | 136,546        | 2,251            |
|          	 |                 |                  |                |                |                  |
+----------------+-----------------+------------------+----------------+----------------+------------------+

Snort Benchmarking
==================

The following is an example to run snort with vectorscan enabled.

.. code-block:: console

  # snort -c  /usr/local/etc/snort/snort.lua --lua 'search_engine.search_method="hyperscan"'
  --daq-dir /usr/local/lib/daq --daq pcap -r /snort_test/inside.pcap
