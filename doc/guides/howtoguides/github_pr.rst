..  SPDX-License-Identifier: Marvell-MIT
    Copyright (c) 2024 Marvell.

Create a Github Pull request
============================

To create a GitHub pull request, follow these steps:

1. **Fork the Repository**: Navigate to the original repository you wish to
contribute to and click on the ‘Fork’ button in the top-right corner. This
creates a copy of the repository in your GitHub account.

2. **Clone the Repository**: Clone the forked repository to your local machine
using the git clone command followed by the URL of your forked repository.

3. **Create a New Branch**: Create a new branch in your local repository using
the git checkout -b command followed by the name of your new branch.

4. **Make Your Changes**: Make the necessary changes in your local repository.

5. **Stage Your Changes**: Stage your changes for a commit using the ``git add .``
command.

6. **Commit Your Changes**: Commit your staged changes using the ``git commit -m``
command followed by a descriptive commit message.

7. **Push Your Changes**: Push your changes to your forked repository on GitHub
using the ``git push origin`` command followed by the name of your branch.

8. **Create a Pull Request**: Navigate to your forked repository on GitHub,
switch to your branch, and click on the ‘New pull request’ button. Fill in the
necessary details and click on ‘Create pull request’.

9. **Pull request via command line**: Pull request can be created and send
via following commands

.. code-block:: console

 # pip3 install git-pull-request     - Install git pull request addon
 # git pull-request --dry-run        - to check if everything is fine
 # git pull-request                  - Create Pull request

.. note::
 # Optional, "Use git pull-request --setup-only" in the cloned official repo to
 create a fork of odp in you git account

10. Your pull request shall be listed in following link:

`<https://github.com/MarvellEmbeddedProcessors/dpu-accelerator-offload/pulls>`_

Remember, each pull request should contain one logical change and the changes
should be isolated to one branch. Also, make sure your code adheres to the
project’s coding standards and guidelines.
