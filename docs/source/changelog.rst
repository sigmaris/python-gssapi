Changelog
=========

Deprecated Versions
-------------------
Versions before 0.6.0 are not recommended as they used ctypesgen instead of CFFI to generate Python
code for interfacing with C, and so were not compatible with Python 3 or PyPy.

0.6.5
^^^^^
* Support for :class:`~gssapi.creds.Credential` construction with `cred_store` param, and
  :meth:`gssapi.creds.Credential.store`.
* :meth:`~gssapi.ctx.Context.unwrap` and :meth:`~gssapi.ctx.Context.verify_mic` now raise
  exceptions if replayed messages are detected, for better security. This behaviour can be modified
  with the `supplementary` parameter to those methods.

0.6.4
^^^^^
* Support for :meth:`~gssapi.creds.Credential.export` and :meth:`~gssapi.creds.Credential.imprt` of
  :class:`~gssapi.creds.Credential` objects.

0.6.3
^^^^^
* Support for :class:`~gssapi.creds.Credential` construction with `password` param, to acquire a
  credential using a password - suitable for acquiring initial Kerberos credentials, for example.
* Fix a bug where names containing non-ASCII characters could be truncated when creating a
  :class:`~gssapi.creds.Name`

0.6.2
^^^^^
* Support for returning supplementary info about replayed or out-of-sequence tokens from
  :meth:`~gssapi.ctx.Context.unwrap` and :meth:`~gssapi.ctx.Context.verify_mic`.
* Add :meth:`~gssapi.ctx.Context.process_context_token`.
* Fix a bug where an incorrect exception could be raised for non-routine errors from the GSSAPI C
  implementation.

0.6.1
^^^^^
* Add specific exception classes for each type of error status in RFC2744.
* Support for Channel Bindings.

0.6.0
^^^^^
* Switch to using `CFFI <https://cffi.readthedocs.org/>`_ for calling the C functions.
* Full compatibility with Python 2.7, PyPy and Python 3.2.

0.5.1
^^^^^
* Discard exceptions in destructors to avoid the interpreter logging them.

0.5.0
^^^^^
* Python 3 support with ctypesgen thanks to Sebastian Deiß.

0.4.1
^^^^^
* Reduce pyasn1 requirement to v0.1.2.
* Fix compatibility with older versions of MIT Kerberos.

0.4.0
^^^^^
* Simplify API, remove BaseName and BaseCredential classes

0.3.0
^^^^^
* Allow GSSException to carry a token, for cases where context establishment fails but a final
  token needs to be communicated to the peer.
* Add support for delegated credentials in AcceptContext.
* Add support for inquiring mechs for a credential.
* Make OIDSet immutable and create a MutableOIDSet subclass.

0.2.5
^^^^^
* Installation fixes for ctypesgen.

0.2.4
^^^^^
* First non-development release.
