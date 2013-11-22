=============
python-gssapi
=============

Python-GSSAPI is a Python binding to the Generic Security Service Application Program Interface
(GSSAPI). The GSSAPI provides a uniform interface to security services which applications can use
without having to worry about implementation details of the underlying mechanisms. The most
commonly used mechanism is Kerberos v5, and this library provides an easy way to use Kerberos
authentication and security from Python code.

The GSSAPI version 2 is specified in `RFC 2743 <http://tools.ietf.org/html/rfc2743>`_ and the C
language bindings which this package is based on are specified in
`RFC 2744 <http://tools.ietf.org/html/rfc2744>`_.

This library is still in a fairly unfinished state; there may be undiscovered bugs or lack of
support for some features. There is a :doc:`TODO <todo>` list of work still to be done on the library.

Contents
========

.. toctree::
   :glob:
   :maxdepth: 2

   examples
   compatibility
   api/gssapi
   todo


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

