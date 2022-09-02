.. role:: bash(code)
   :language: bash

#######
fasteth
#######

.. image::  https://github.com/Alcibiades-Capital/fasteth/workflows/Tests/badge.svg
    :target:  https://github.com/Alcibiades-Capital/fasteth/actions?workflow=Tests

********
Abstract
********

:bash:`fasteth` is an asynchronous python abstraction layer for the Ethereum
JSON RPC. It biases towards using native python types and dataclasses to represent
Ethereum data, whilst remaining lightweight and making minimal assumptions.

*****
Goals
*****

The motivation for creating this is to provide fast, asynchronous, native
python, access to the Ethereum JSON RPC. Extant python libraries are synchronous and
provide additional abstraction which may not always be needed. This library favors
speed and asynchronicity.

******
Status
******

This project is still a work in progress.

***************
Further Reading
***************

TODO(These should be links)

Quickstart
==========

This project aims to make it easy to make async requests and get responses back from the
Ethereum JSON RPC. Here is a simple example:

.. code-block:: bash

    pip install fasteth

.. code-block:: python

    import asyncio
    from fasteth import AsyncEthereumJSONRPC

    async def do_requests():
        async with AsyncEthereumJSONRPC() as rpc:
            print(await rpc.network_version())

    asyncio.run(do_requests())

See the :bash:`fastapi` docs for a
`great explanation <https://fastapi.tiangolo.com/async/#asynchronous-code>`_ of
async/concurrency. As an aside, :bash:`fastapi` was the inspiration for the name
:bash:`fasteth`.


Getting Involved
================

PR your changes :).

Developer Guide
---------------

You'll need poetry.

.. code-block:: bash

    poetry install
    poetry shell

You'll also need a running instance of :bash:`ganache-cli` and in should be started
with the argument :bash:`--networkId 1337`

Running the pre-commit hooks on demand
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Initial setup:

.. code-block:: bash

    pre-commit install
    pre-commit install --hook-type pre-push

Then:

.. code-block:: bash

    pre-commit run --all-files

This will run:

During commit

* Check if there are merge conflicts.
* Check if there are debug statements, we don't want those in checked in code
* Lint with :bash:`flake8`.
* Use :bash:`black` to format the code, modifies files in-place if the code in the
  changeset is not already black compliant and fails the hook.

During push

* All of the above runs also :bash:`pytest` with verbose flag
  (if any python files have changed).

Building the PyPI package
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    poetry build

It's that simple.
