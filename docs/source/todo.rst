TODO
====

* Make ``python setup.py develop`` install the generated _h.py file(s) in gssapi/headers
* Support channel bindings
* Implement ``Context.process_context_token``
* Return ``S_DUPLICATE_TOKEN``, etc information from unwrap and verify_mic
* ``gss_add_cred`` support?
* Add support for useful GSSAPI / krb5 extensions, e.g. storing delegated credentials
* Create more specific subclasses of GSSCException for bad mech, missing credentials, etc
* Find earliest version of pyasn1 that supports what we need and reduce required version
