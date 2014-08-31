Compatibility
=============
This package uses `cffi <https://cffi.readthedocs.org/>`_ to call into the underlying GSSAPI C
library on the platform. It has been tested to work on Linux with the MIT GSSAPI implementation
and Mac OS X 10.8 and 10.9 with the Heimdal GSSAPI implementation. Other versions of Mac OS X, and
the Heimdal implementation on Linux should work but have not been tested.

The install process requires generating C interface definitions from the GSSAPI C-headers using
:mod:`cffi`. In order to do this, the development headers for your GSSAPI implementation must be
installed and a C compiler must be available at install time. On CPython you need to build the C
extension module, so you need ``python-dev`` and ``libffi-dev`` installed in order to install
:mod:`cffi`.

Support for Optional Features
-----------------------------
There are certain optional features which may or not be enabled depending on support in the
underlying GSSAPI C library on the platform. If these features are not supported, the corresponding
constants or classes will not be present in the Python package, or methods will raise
:exc:`~exceptions.NotImplementedError` if you attempt to use a feature that is not implemented.

These optional features are:

* :const:`gssapi.C_DELEG_POLICY_FLAG` - in MIT Kerberos, this is only available from v1.7 onwards.
* :const:`gssapi.C_AF_INET6` and :class:`~gssapi.chanbind.IPv6ChannelBindings` - This is not defined
  by MIT Kerberos, only Heimdal.
* :class:`~gssapi.creds.Credential` construction with `password` param - this is only supported in
  MIT Kerberos v1.9 onwards, and in Heimdal v1.5 and above.
* :meth:`gssapi.creds.Credential.store` without `cred_store` param - this requires support for
  ``gss_store_cred`` from `RFC5588 <http://tools.ietf.org/html/rfc5588.html>`_ which is implemented
  in MIT Kerberos v1.8 onwards and Heimdal v1.3 onwards.
* :class:`~gssapi.creds.Credential` construction with `cred_store` param, and
  :meth:`gssapi.creds.Credential.store` with the `cred_store` param - these require support
  for `credential stores <http://k5wiki.kerberos.org/wiki/Projects/Credential_Store_extensions>`_
  which is implemented in MIT Kerberos v1.11 onwards.
