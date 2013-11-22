:mod:`gssapi` Package
=====================

.. py:module:: gssapi

In general, all the useful functions, classes and constants from the subpackages of :mod:`gssapi`
such as :class:`~gssapi.ctx.InitContext`, :class:`~gssapi.names.Name`, etc, are available as
members of the :mod:`gssapi` package, so you can do:

>>> from gssapi import Credential, Name, AcceptContext

:mod:`gssapi` Module
--------------------

Flags
^^^^^

The flags here have two uses: they can be bitwise-ORed and passed as the `req_flags` parameter to
:class:`~gssapi.ctx.InitContext` to request that the corresponding feature is enabled, and they are
set as the :attr:`~gssapi.ctx.Context.flags` attribute of an established security context to
indicate that the corresponding feature has been negotiated and enabled.

.. py:data:: C_DELEG_FLAG

    Flag indicating that credential delegation from the initiator to the acceptor should be used,
    or has been used if this flag is set on an established context.

.. py:data:: C_MUTUAL_FLAG

    Flag indicating that mutual authentication of the acceptor to the initiator (as well as vice
    versa) should be requested when initiating a connection, or has been used if this flag is set
    on an established context.

.. py:data:: C_REPLAY_FLAG

    Flag indicating that message replay detection should be requested when initiating a connection,
    or has been used if this flag is set on an established context.

.. py:data:: C_SEQUENCE_FLAG

    Flag indicating that out-of-sequence message detection should be requested when initiating a
    connection, or has been used if this flag is set on an established context.

.. py:data:: C_CONF_FLAG

    Flag indicating that message confidentiality services (encryption) should be requested when
    initiating a connection, or has been used if this flag is set on an established context.

.. py:data:: C_INTEG_FLAG

    Flag indicating that message integrity services (signing) should be requested when initiating a
    connection, or has been used if this flag is set on an established context.

.. py:data:: C_ANON_FLAG

    Flag requesting that the initiator's identity should be concealed from the acceptor, or
    indicating that the initiator's identity was not revealed to the acceptor on an established
    context.

.. py:data:: C_PROT_READY_FLAG

    Flag indicating that message confidentiality or integrity services are available on a context,
    which may be set even before the context is fully established, if the services can be used at
    that point.

.. py:data:: C_TRANS_FLAG

    Flag indicating that a context is exportable and importable between different processes.

.. py:data:: C_DELEG_POLICY_FLAG

    Flag used to request that credential delegation be used, but only to acceptors that are
    permitted to be delegated to by some mechanism-specific policy (e.g. the OK-AS-DELEGATE ticket
    flag in Kerberos, which can be set on services to indicate they are trusted for delegation).
    This flag is only used to request this behaviour from :class:`~gssapi.ctx.InitContext`.

    If :const:`C_DELEG_FLAG` is set, it overrides this flag and causes delegation to always be used,
    regardless of policy.

Usage Constants
^^^^^^^^^^^^^^^

.. py:data:: C_BOTH

    Constant which can be passed as the `usage` parameter to :class:`~gssapi.creds.Credential` to
    acquire a credential suitable for both initiating and accepting security contexts.

.. py:data:: C_INITIATE

    Constant which can be passed as the `usage` parameter to :class:`~gssapi.creds.Credential` to
    acquire a credential suitable for initiating security contexts only.

.. py:data:: C_ACCEPT

    Constant which can be passed as the `usage` parameter to :class:`~gssapi.creds.Credential` to
    acquire a credential suitable for accepting security contexts only.

.. py:data:: C_INDEFINITE

    Represents an indefinite lifetime for a security context or credential; can be passed as the
    `lifetime` parameter to :class:`~gssapi.creds.Credential` to request a credential with the
    maximum possible lifetime.

Name Types
^^^^^^^^^^

.. py:data:: C_NT_USER_NAME

    Represents a local username. The value should be a simple username string like "dave".

.. py:data:: C_NT_MACHINE_UID_NAME

    On UNIX-like systems, represents a numeric UID. The value should be an int.

.. py:data:: C_NT_STRING_UID_NAME

    As above, but the value should be a decimal string representation of the numeric UID like "501".

.. py:data:: C_NT_HOSTBASED_SERVICE

    Represents a service on a certain host. The value should be a string of the form "service"
    (normally indicating the service is on this host) or "service\@hostname". This is normally used
    to create the `peer_name` parameter when initiating a security context, and is the most common
    method of targeting services.

.. py:data:: C_NT_ANONYMOUS

    Represents an anonymous name. The value is ignored.

.. py:data:: C_NT_EXPORT_NAME

    Represents a mechanism name which has previously been exported by
    :meth:`~gssapi.names.MechName.export`. The value should be the bytestring returned by
    :meth:`~gssapi.names.MechName.export`.

Status Codes
^^^^^^^^^^^^

These status codes may be returned as the :attr:`~gssapi.error.GSSCException.maj_status` attribute
of a :class:`~gssapi.error.GSSCException` raised by various GSSAPI operations. For a full reference
to the meaning of the various status codes, check
`RFC 2744 Section 3.9.1 <http://tools.ietf.org/html/rfc2744#section-3.9.1>`_ - the constants here
are equivalent to the status codes listed in the RFC without the `GSS_` prefix.

.. py:data:: S_CALL_INACCESSIBLE_READ
.. py:data:: S_CALL_INACCESSIBLE_WRITE
.. py:data:: S_CALL_BAD_STRUCTURE
.. py:data:: S_BAD_MECH
.. py:data:: S_BAD_NAME
.. py:data:: S_BAD_NAMETYPE
.. py:data:: S_BAD_BINDINGS
.. py:data:: S_BAD_STATUS
.. py:data:: S_BAD_SIG
.. py:data:: S_NO_CRED
.. py:data:: S_NO_CONTEXT
.. py:data:: S_DEFECTIVE_TOKEN
.. py:data:: S_DEFECTIVE_CREDENTIAL
.. py:data:: S_CREDENTIALS_EXPIRED
.. py:data:: S_CONTEXT_EXPIRED
.. py:data:: S_FAILURE
.. py:data:: S_BAD_QOP
.. py:data:: S_UNAUTHORIZED
.. py:data:: S_UNAVAILABLE
.. py:data:: S_DUPLICATE_ELEMENT
.. py:data:: S_NAME_NOT_MN
.. py:data:: S_CONTINUE_NEEDED
.. py:data:: S_DUPLICATE_TOKEN
.. py:data:: S_OLD_TOKEN
.. py:data:: S_UNSEQ_TOKEN
.. py:data:: S_GAP_TOKEN
.. py:data:: S_CRED_UNAVAIL

.. py:data:: S_COMPLETE

    This status code does not represent an error and shouldn't be used as the
    :attr:`~gssapi.error.GSSCException.maj_status` attribute of a
    :class:`~gssapi.error.GSSCException`, as it represents successful completion.

:mod:`creds` Module
-------------------

.. automodule:: gssapi.creds
    :members:
    :show-inheritance:

:mod:`ctx` Module
-----------------

.. automodule:: gssapi.ctx
    :members:
    :show-inheritance:

:mod:`error` Module
-------------------

.. automodule:: gssapi.error
    :members:
    :show-inheritance:

:mod:`names` Module
-------------------

.. automodule:: gssapi.names
    :members:
    :show-inheritance:

:mod:`oids` Module
------------------

.. automodule:: gssapi.oids
    :members:
    :show-inheritance:
