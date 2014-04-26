from __future__ import absolute_import

from .bindings import C, ffi, GSS_ERROR
from .error import _exception_for_status
from .names import Name
from .oids import OIDSet


def _release_gss_cred_id_t(cred):
    if cred[0]:
        C.gss_release_cred(ffi.new('OM_uint32[1]'), cred)


class Credential(object):
    """
    Acquire a reference to a pre-existing credential. Use this to create a credential with a
    specific name to use in an :class:`AcceptContext` or to select a specific identity from the
    user's credential set to use as an initiator credential.

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
    :type usage: One of :data:`~gssapi.C_INITIATE`, :data:`~gssapi.C_ACCEPT` or :data:`~gssapi.C_BOTH`
    :returns: a :class:`Credential` object referring to the requested credential.
    :raises: :exc:`~gssapi.error.GSSException` if there is an error acquiring a reference to the
        credential.
    """

    def __init__(self, desired_name=C.GSS_C_NO_NAME, lifetime=C.GSS_C_INDEFINITE,
                 desired_mechs=C.GSS_C_NO_OID_SET, usage=C.GSS_C_BOTH):
        super(Credential, self).__init__()

        self._mechs = None
        if isinstance(desired_name, ffi.CData) and ffi.typeof(desired_name) == ffi.typeof('gss_cred_id_t[1]'):
            # wrapping an existing gss_cred_id_t, exit early
            self._cred = ffi.gc(desired_name, _release_gss_cred_id_t)
            return
        else:
            self._cred = ffi.new('gss_cred_id_t[1]')

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
