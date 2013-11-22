from __future__ import absolute_import

from ctypes import cast, byref, c_uint

from .headers.gssapi_h import (
    GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_NO_CREDENTIAL,
    GSS_ERROR, GSS_C_INITIATE, GSS_C_ACCEPT, GSS_C_BOTH,
    OM_uint32, gss_cred_id_t, gss_name_t, gss_OID_set, gss_cred_usage_t,
    gss_acquire_cred, gss_inquire_cred,
    gss_release_cred, gss_release_oid_set, gss_release_name
)
from .error import GSSCException
from .names import Name
from .oids import OIDSet


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

    def __init__(self, desired_name=GSS_C_NO_NAME, lifetime=GSS_C_INDEFINITE,
                 desired_mechs=GSS_C_NO_OID_SET, usage=GSS_C_BOTH):
        super(Credential, self).__init__()

        self._mechs = None
        if type(desired_name) == gss_cred_id_t:
            # wrapping an existing gss_cred_id_t, exit early
            self._cred = desired_name
            return
        else:
            self._cred = gss_cred_id_t()

        minor_status = OM_uint32()

        if isinstance(desired_name, Name):
            desired_name = desired_name._name
        elif desired_name == GSS_C_NO_NAME:
            desired_name = cast(desired_name, gss_name_t)
        else:
            raise TypeError(
                "Expected a Name object or C_NO_NAME, got {0}.".format(type(desired_name))
            )

        if isinstance(desired_mechs, OIDSet):
            desired_mechs = desired_mechs._oid_set
        elif desired_mechs == GSS_C_NO_OID_SET:
            desired_mechs = cast(desired_mechs, gss_OID_set)
        else:
            raise TypeError(
                "Expected an OIDSet object or C_NO_OID_SET, got {0}.".format(type(desired_mechs))
            )

        actual_mechs = gss_OID_set()
        time_rec = c_uint()

        retval = gss_acquire_cred(
            byref(minor_status),
            desired_name,
            OM_uint32(lifetime),
            desired_mechs,
            gss_cred_usage_t(usage),
            byref(self._cred),
            byref(actual_mechs),
            byref(time_rec)
        )
        try:
            if GSS_ERROR(retval):
                raise GSSCException(retval, minor_status)

            self._mechs = OIDSet(actual_mechs)
        except:
            if actual_mechs:
                gss_release_oid_set(byref(minor_status), byref(actual_mechs))
            self._release()
            raise

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
        minor_status = OM_uint32()

        name = gss_name_t()
        lifetime = OM_uint32()
        usage = gss_cred_usage_t()
        mechs = gss_OID_set()

        retval = gss_inquire_cred(
            byref(minor_status),
            self._cred,
            byref(name) if get_name else None,
            byref(lifetime) if get_lifetime else None,
            byref(usage) if get_usage else None,
            byref(mechs) if get_mechs else None
        )

        try:
            if GSS_ERROR(retval):
                raise GSSCException(retval, minor_status)
            if get_name:
                nameobj = Name(name)
            if get_mechs:
                mechsobj = OIDSet(mechs)
            return (
                nameobj if get_name else None,
                lifetime.value if get_lifetime else None,
                usage.value if get_usage else None,
                mechsobj if get_mechs else None
            )

        except:
            if name:
                gss_release_name(byref(minor_status), byref(name))
            if mechs:
                gss_release_oid_set(byref(minor_status), byref(mechs))
            raise

    def _release(self):
        if hasattr(self, '_cred') and self._cred:
            minor_status = OM_uint32()
            gss_release_cred(byref(minor_status), byref(self._cred))
            self._cred = cast(GSS_C_NO_CREDENTIAL, gss_cred_id_t)

    def __del__(self):
        self._release()
