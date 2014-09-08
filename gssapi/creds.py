from __future__ import absolute_import

import six

from .bindings import C, ffi, GSS_ERROR, _buf_to_str
from .error import _exception_for_status
from .names import Name
from .oids import OID, OIDSet


def _release_gss_cred_id_t(cred):
    if cred[0]:
        C.gss_release_cred(ffi.new('OM_uint32[1]'), cred)


def _make_kv_set(cred_store):
    if isinstance(cred_store, dict):
        cred_store = cred_store.items()
    kv_count = len(cred_store)
    kv_array = ffi.new('gss_key_value_element_desc[]', kv_count)
    c_strings = []
    for index, (key, value) in enumerate(cred_store):
        if isinstance(key, bytes):
            key_c_str = ffi.new('char[]', key)
        elif isinstance(key, six.string_types):
            key_c_str = ffi.new('char[]', key.encode())
        else:
            raise TypeError("Expected a string or bytes, got {0}".format(type(key)))

        if isinstance(value, bytes):
            val_c_str = ffi.new('char[]', value)
        elif isinstance(value, six.string_types):
            val_c_str = ffi.new('char[]', value.encode())
        else:
            raise TypeError("Expected a string or bytes, got {0}".format(type(value)))

        c_strings.extend([key_c_str, val_c_str])  # keep references to memory
        kv_array[index].key = key_c_str
        kv_array[index].value = val_c_str
    cred_store_kv_set = ffi.new('gss_key_value_set_desc[1]')
    cred_store_kv_set[0].count = kv_count
    cred_store_kv_set[0].elements = kv_array
    return c_strings, kv_array, cred_store_kv_set


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

    Acquiring a credential from a specific credential store is also an extension to the GSSAPI and
    may not be supported by the underlying implementation (see :doc:`/compatibility`). If
    unsupported, :exc:`~exceptions.NotImplementedError` will be raised if the `cred_store`
    parameter is provided.

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
    :param cred_store: Optional dict or list of (key, value) pairs indicating the credential store
        to use. The interpretation of these values will be mechanism-specific. If the `password`
        parameter is passed, this parameter will be ignored.
    :type cred_store: dict, or list of (str, str)
    :returns: a :class:`Credential` object referring to the requested credential.
    :raises: :exc:`~gssapi.error.GSSException` if there is an error acquiring a reference to the
        credential.

        :exc:`~exceptions.NotImplementedError` if a password is provided but the underlying GSSAPI
        implementation does not support acquiring credentials with a password, or if the
        `cred_store` parameter is provided but the underlying GSSAPI implementation does not support
        the ``gss_acquire_cred_from`` C function.
    """

    def __init__(self, desired_name=C.GSS_C_NO_NAME, lifetime=C.GSS_C_INDEFINITE,
                 desired_mechs=C.GSS_C_NO_OID_SET, usage=C.GSS_C_BOTH, password=None, cred_store=None):
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
        if cred_store is not None and not hasattr(C, 'gss_acquire_cred_from'):
            raise NotImplementedError("The GSSAPI implementation does not support"
                                      "gss_acquire_cred_from")

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
        elif cred_store is not None:
            c_strings, elements, cred_store_kv_set = _make_kv_set(cred_store)

            retval = C.gss_acquire_cred_from(
                minor_status,
                desired_name,
                ffi.cast('OM_uint32', lifetime),
                desired_mechs,
                ffi.cast('gss_cred_usage_t', usage),
                cred_store_kv_set,
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
            credential.

            :exc:`NotImplementedError` if the underlying GSSAPI implementation does not
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
            credential.

            :exc:`NotImplementedError` if the underlying GSSAPI implementation does not
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

    def store(self, usage=None, mech=None, overwrite=False, default=False, cred_store=None):
        """
        Stores this credential into a 'credential store'. It can either store this credential in
        the default credential store, or into a specific credential store specified by a set of
        mechanism-specific key-value pairs. The former method of operation requires that the
        underlying GSSAPI implementation supports the ``gss_store_cred`` C function, the latter
        method requires support for the ``gss_store_cred_into`` C function.

        :param usage: Optional parameter specifying whether to store the initiator, acceptor, or
            both usages of this credential. Defaults to the value of this credential's
            :attr:`usage` property.
        :type usage: One of :data:`~gssapi.C_INITIATE`, :data:`~gssapi.C_ACCEPT` or
            :data:`~gssapi.C_BOTH`
        :param mech: Optional parameter specifying a single mechanism to store the credential
            element for. If not supplied, all mechanisms' elements in this credential will be
            stored.
        :type mech: :class:`~gssapi.oids.OID`
        :param overwrite: If True, indicates that any credential for the same principal in the
            credential store should be overwritten with this credential.
        :type overwrite: bool
        :param default: If True, this credential should be made available as the default
            credential when stored, for acquisition when no `desired_name` parameter is passed
            to :class:`Credential` or for use when no credential is passed to
            :class:`~gssapi.ctx.InitContext` or :class:`~gssapi.ctx.AcceptContext`. This is only
            an advisory parameter to the GSSAPI implementation.
        :type default: bool
        :param cred_store: Optional dict or list of (key, value) pairs indicating the credential
            store to use. The interpretation of these values will be mechanism-specific.
        :type cred_store: dict, or list of (str, str)
        :returns: A pair of values indicating the set of mechanism OIDs for which credential
            elements were successfully stored, and the usage of the credential that was stored.
        :rtype: tuple(:class:`~gssapi.oids.OIDSet`, int)
        :raises: :exc:`~gssapi.error.GSSException` if there is a problem with storing the
            credential.

            :exc:`NotImplementedError` if the underlying GSSAPI implementation does not
            support the ``gss_store_cred`` or ``gss_store_cred_into`` C functions.
        """
        if usage is None:
            usage = self.usage
        if isinstance(mech, OID):
            oid_ptr = ffi.addressof(mech._oid)
        else:
            oid_ptr = ffi.cast('gss_OID', C.GSS_C_NO_OID)

        minor_status = ffi.new('OM_uint32[1]')
        elements_stored = ffi.new('gss_OID_set[1]')
        usage_stored = ffi.new('gss_cred_usage_t[1]')

        if cred_store is None:
            if not hasattr(C, 'gss_store_cred'):
                raise NotImplementedError("The GSSAPI implementation does not support "
                                          "gss_store_cred")

            retval = C.gss_store_cred(
                minor_status,
                self._cred[0],
                ffi.cast('gss_cred_usage_t', usage),
                oid_ptr,
                ffi.cast('OM_uint32', overwrite),
                ffi.cast('OM_uint32', default),
                elements_stored,
                usage_stored
            )
        else:
            if not hasattr(C, 'gss_store_cred_into'):
                raise NotImplementedError("The GSSAPI implementation does not support "
                                          "gss_store_cred_into")

            c_strings, elements, cred_store_kv_set = _make_kv_set(cred_store)

            retval = C.gss_store_cred_into(
                minor_status,
                self._cred[0],
                ffi.cast('gss_cred_usage_t', usage),
                oid_ptr,
                ffi.cast('OM_uint32', overwrite),
                ffi.cast('OM_uint32', default),
                cred_store_kv_set,
                elements_stored,
                usage_stored
            )
        try:
            if GSS_ERROR(retval):
                if oid_ptr:
                    raise _exception_for_status(retval, minor_status[0], oid_ptr)
                else:
                    raise _exception_for_status(retval, minor_status[0])
        except:
            if elements_stored[0]:
                C.gss_release_oid_set(minor_status, elements_stored)
            raise

        return (OIDSet(elements_stored), usage_stored[0])
