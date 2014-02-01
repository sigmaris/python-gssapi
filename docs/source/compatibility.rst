Compatibility
=============
This package uses :mod:`ctypes` to call into the underlying GSSAPI C library on the platform. It
has been tested to work on Linux with the MIT GSSAPI implementation and Mac OS X 10.8 and 10.9 with
the Heimdal GSSAPI implementation. Other versions of Mac OS X, and the Heimdal implementation on
Linux should work but have not been tested.

Support for acquiring credentials using a password requires the ``gss_acquire_cred_with_password``
function to be implemented by the GSSAPI C library; this is supported in the MIT implementation in
versions 1.9 and above, and in the Heimdal implementation in version 1.5 and above.

The install process requires generating Python interface files from the GSSAPI C-headers using the
`ctypesgen <https://code.google.com/p/ctypesgen/>`_ package. In order to do this, the development
headers for your GSSAPI implementation must be installed and GCC must be available at install time.
