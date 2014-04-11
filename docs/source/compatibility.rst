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
