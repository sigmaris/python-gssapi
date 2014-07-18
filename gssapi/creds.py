from __future__ import absolute_import

import six

from .bindings import C, ffi, GSS_ERROR, _buf_to_str
from .error import _exception_for_status
from .names import Name
from .oids import OIDSet


def _release_gss_cred_id_t(cred):
    if cred[0]:
        C.gss_release_cred(ffi.new('OM_uint32[1]'), cred)


class Credential(object):
    """
    Acquire a reference to a credential. Use this to select a credential with a specific name to
    use in an :class:`~gssapi.ctx.AcceptContext`, to select a specific identity from the user's
    credential set to use as an initiator credential, or to obtain a credential using a password.

    Note that obtaining a credential using a password is a nonstandard extension to the GSSAPI and
    may not be supported by the underlying implementation (see :doc:`/compatibility`); in that case
    :exc:`~exceptions.NotImplementedError` will be raised if a `password` parameter is passed to
    the Credential constructor. Also, if the `password` parameter is passed, normally the
    `desired_name` parameter must also be provided.

    :param desired_name: Optional Name to acquire a credential for. Defaults to the user's
        default identity.
    :type desired_name: :class:`~gssapi.names.Name`
    :param lifetime: Optional lifetime for the acquired credential, in seconds. Defaults to the
        maximum possible lifetime.
    :type lifetime: int
    :param desired_mechs: Optional set of mechanisms to obtain credentials for.
    :type desired_mechs: :class:`~gssapi.oids.OIDSet`
    :param usage: Flag indicating whether to obtain a credential which can be used as an
        initiator credential, an acceptor credential, or both.
    :type usage: One of :data:`~gssapi.C_INITIATE`, :data:`~gssapi.C_ACCEPT` or
        :data:`~gssapi.C_BOTH`
    :param password: Optional password to use. If this parameter is provided, the library will
        attempt to acquire a new credential using the given password. Otherwise, a reference to an
        existing credential will be acquired.
    :type password: bytes
    :returns: a :class:`Credential` object referring to the requested credential.
    :raises: :exc:`~gssapi.error.GSSException` if there is an error acquiring a reference to the
        credential.

        :exc:`~exceptions.NotImplementedError` if a password is provided but the underlying GSSAPI
        implementation does not support acquiring credentials with a password.
    """

    def __init__(self, desired_name=C.GSS_C_NO_NAME, lifetime=C.GSS_C_INDEFINITE,
                 desired_mechs=C.GSS_C_NO_OID_SET, usage=C.GSS_C_BOTH, password=None):
        super(Credential, self).__init__()

        self._mechs = None
        if isinstance(desired_name, ffi.CData) and ffi.typeof(desired_name) == ffi.typeof('gss_cred_id_t[1]'):
            # wrapping an existing gss_cred_id_t, exit early
            self._cred = ffi.gc(desired_name, _release_gss_cred_id_t)
            return
        else:
            self._cred = ffi.new('gss_cred_id_t[1]')

        if password is not None and not hasattr(C, 'gss_acquire_cred_with_password'):
            raise NotImplementedError("The GSSAPI implementation does not support "
                                      "gss_acquire_cred_with_password")

        minor_status = ffi.new('OM_uint32[1]')

        if isinstance(desired_name, Name):
            desired_name = desired_name._name[0]
        elif desired_name == C.GSS_C_NO_NAME:
            desired_name = ffi.cast('gss_name_t', desired_name)
        else:
            raise TypeError(
                "Expected a Name object or C_NO_NAME, got {0}.".format(type(desired_name))
            )

        if isinstance(desired_mechs, OIDSet):
            desired_mechs = desired_mechs._oid_set[0]
        elif desired_mechs == C.GSS_C_NO_OID_SET:
            desired_mechs = ffi.cast('gss_OID_set', desired_mechs)
        else:
            raise TypeError(
                "Expected an OIDSet object or C_NO_OID_SET, got {0}.".format(type(desired_mechs))
            )

        actual_mechs = ffi.new('gss_OID_set[1]')
        time_rec = ffi.new('OM_uint32[1]')

        if password is not None:
            if isinstance(password, bytes):
                pw_bytes = password
            elif isinstance(password, six.string_types):
                pw_bytes = password.encode()
            else:
                raise TypeError("password must be a string, not {0}".format(type(password)))

            pw_buffer = ffi.new('gss_buffer_desc[1]')
            pw_buffer[0].length = len(pw_bytes)
            c_str_pw = ffi.new('char[]', pw_bytes)
            pw_buffer[0].value = c_str_pw

            retval = C.gss_acquire_cred_with_password(
                minor_status,
                desired_name,
                pw_buffer,
                ffi.cast('OM_uint32', lifetime),
                desired_mechs,
                ffi.cast('gss_cred_usage_t', usage),
                self._cred,
                actual_mechs,
                time_rec
            )
        else:
            retval = C.gss_acquire_cred(
                minor_status,
                desired_name,
                ffi.cast('OM_uint32', lifetime),
                desired_mechs,
                ffi.cast('gss_cred_usage_t', usage),
                self._cred,
                actual_mechs,
                time_rec
            )
        self._cred = ffi.gc(self._cred, _release_gss_cred_id_t)

        if GSS_ERROR(retval):
            if actual_mechs[0]:
                C.gss_release_oid_set(minor_status, actual_mechs)
            raise _exception_for_status(retval, minor_status[0])

        self._mechs = OIDSet(actual_mechs)

    @property
    def name(self):
        """
        The name associated with the credential.

        :type: :class:`~gssapi.names.Name`
        """
        return self._inquire(True, False, False, False)[0]

    @property
    def lifetime(self):
        """
        The lifetime in seconds for which this credential is valid.
        """
        return self._inquire(False, True, False, False)[1]

    @property
    def usage(self):
        """
        The usage of the credential, either :const:`gssapi.C_INITIATE`, :const:`gssapi.C_ACCEPT` or
        :const:`gssapi.C_BOTH`.
        """
        return self._inquire(False, False, True, False)[2]

    @property
    def mechs(self):
        """
        The set of mechanisms supported by the credential.

        :type: :class:`~gssapi.oids.OIDSet`
        """
        if not self._mechs:
            self._mechs = self._inquire(False, False, False, True)[3]
        return self._mechs

    def _inquire(self, get_name, get_lifetime, get_usage, get_mechs):
        minor_status = ffi.new('OM_uint32[1]')

        name = ffi.new('gss_name_t[1]') if get_name else ffi.NULL
        lifetime = ffi.new('OM_uint32[1]') if get_lifetime else ffi.NULL
        usage = ffi.new('gss_cred_usage_t[1]') if get_usage else ffi.NULL
        mechs = ffi.new('gss_OID_set[1]') if get_mechs else ffi.NULL

        retval = C.gss_inquire_cred(
            minor_status,
            self._cred[0],
            name,
            lifetime,
            usage,
            mechs
        )

        try:
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])
        except:
            if get_name and name[0]:
                C.gss_release_name(minor_status, name)
            if get_mechs and mechs[0]:
                C.gss_release_oid_set(minor_status, mechs)
            raise

        if get_name:
            nameobj = Name(name)
        if get_mechs:
            mechsobj = OIDSet(mechs)
        return (
            nameobj if get_name else None,
            lifetime[0] if get_lifetime else None,
            usage[0] if get_usage else None,
            mechsobj if get_mechs else None
        )

    def export(self):
        """
        Serializes this credential into a byte string, which can be passed to :meth:`imprt` in
        another process in order to deserialize the byte string back into a credential. Exporting
        a credential does not destroy it.

        :returns: The serialized token representation of this credential.
        :rtype: bytes
        :raises: :exc:`~gssapi.error.GSSException` if there is a problem with exporting the
            credential. :exc:`NotImplementedError` if the underlying GSSAPI implementation does not
            support the ``gss_export_cred`` C function.
        """
        if not hasattr(C, 'gss_export_cred'):
            raise NotImplementedError("The GSSAPI implementation does not support gss_export_cred")

        minor_status = ffi.new('OM_uint32[1]')
        output_buffer = ffi.new('gss_buffer_desc[1]')
        retval = C.gss_export_cred(minor_status, self._cred[0], output_buffer)
        try:
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])

            return _buf_to_str(output_buffer[0])
        finally:
            if output_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_buffer)

    @classmethod
    def imprt(cls, token):
        """
        Deserializes a byte string token into a :class:`Credential` object. The token must have
        previously been exported by the same GSSAPI implementation as is being used to import it.

        :param token: A token previously obtained from the :meth:`export` of another
            :class:`Credential` object.
        :type token: bytes
        :returns: A :class:`Credential` object constructed from the token.
        :raises: :exc:`~gssapi.error.GSSException` if there is a problem with importing the
            credential. :exc:`NotImplementedError` if the underlying GSSAPI implementation does not
            support the ``gss_import_cred`` C function.
        """
        if not hasattr(C, 'gss_import_cred'):
            raise NotImplementedError("The GSSAPI implementation does not support gss_import_cred")

        minor_status = ffi.new('OM_uint32[1]')

        token_buffer = ffi.new('gss_buffer_desc[1]')
        token_buffer[0].length = len(token)
        c_str_token = ffi.new('char[]', token)
        token_buffer[0].value = c_str_token

        imported_cred = ffi.new('gss_cred_id_t[1]')

        retval = C.gss_import_cred(minor_status, token_buffer, imported_cred)
        try:
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])

            return cls(imported_cred)
        except:
            _release_gss_cred_id_t(imported_cred)
            raise
