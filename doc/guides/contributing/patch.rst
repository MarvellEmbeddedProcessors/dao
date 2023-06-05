..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Submitting Patches
==================

Before submitting a new patch, it is imperative to adhere to the following
guidelines to ensure the patch is up to the project’s standards and can be
seamlessly integrated into the existing codebase.

1. Coding standards mentioned in following link should be strictly followed
to maintain the quality and readability of the codebase

:doc:`DAO coding standards <./coding>`

2. Prior to submitting a patch, the `<Linux source>/script/checkpatch.pl` script
must be utilized to ensure the patch adheres to the project’s coding standards
and guidelines

3. Code must be meticulously documented using the Doxygen style to ensure
clarity and ease of understanding for future reference and maintenance.

4. Commit messages should be highly descriptive, narrating the mechanics of the
change in detail. The associated comments should elaborate on the problem, its
symptoms, and if required, the rationale behind the chosen solution approach.

5. Each logical change should be isolated into an individual patch. For instance,
if your modifications encompass both bug fixes and performance enhancements for
a single library or application, it is advisable to segregate those alterations
into two or more distinct patches.

6. Follow steps drafted to create and send the pull request.

:doc:`Steps to create PR <../howtoguides/github_pr>`
