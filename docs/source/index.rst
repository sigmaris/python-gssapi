python-gssapi
=============
Python-GSSAPI is a Python binding to the Generic Security Service Application Program Interface
(GSSAPI). The GSSAPI provides a uniform interface to security services which applications can use
without having to worry about implementation details of the underlying mechanisms. The most
commonly used mechanism is Kerberos v5, and this package provides an easy way to use Kerberos
authentication and security from Python code.

The GSSAPI version 2 is specified in `RFC 2743 <http://tools.ietf.org/html/rfc2743>`_ and the C
language bindings which this package is based on are specified in
`RFC 2744 <http://tools.ietf.org/html/rfc2744>`_.

Goals
-----
The goals for this package are to provide a GSSAPI wrapper which is:

* Pythonic and object-oriented.
* Compatible with Python 2 and 3 on both CPython and PyPy.
* Covering the full range of features in the GSSAPI.

This package is implemented using CFFI for compatibility with PyPy, and is also compatible and
tested with Python 3.

This package also covers the full scope of the GSSAPI's features including delegating credentials,
selection of different mechanisms, different name types, MICs, channel bindings and anonymous
authentication.

In contrast with some other Kerberos or GSSAPI packages, which require the user to do manual memory
management and permit memory leaks, memory associated with objects in this package is freed
automatically when the objects are garbage-collected by Python.

Contents
========

.. toctree::
   :glob:
   :maxdepth: 2

   examples
   compatibility
   contributors
   api/gssapi
   changelog
   todo


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

