from __future__ import absolute_import

from ctypes import cast, byref, c_uint

from .gssapi_h import (
    GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_NO_CREDENTIAL,
    GSS_ERROR, GSS_C_INITIATE, GSS_C_ACCEPT, GSS_C_BOTH,
    OM_uint32, gss_cred_id_t, gss_name_t, gss_OID_set, gss_cred_usage_t,
    gss_acquire_cred, gss_inquire_cred,
    gss_release_cred, gss_release_oid_set, gss_release_name
)
from .error import GSSException
from .names import BaseName
from .oids import OIDSet


class BaseCredential(object):
    """Wraps a GSS credential handle (gss_cred_id_t)"""

    def __init__(self):
        super(BaseCredential, self).__init__()
        self._cred = gss_cred_id_t()

    @property
    def name(self):
        return self._inquire(True, False, False)[0]

    @property
    def lifetime(self):
        return self._inquire(False, True, False)[1]

    @property
    def usage(self):
        return self._inquire(False, False, True)[2]

    def _inquire(self, get_name, get_lifetime, get_usage):
        minor_status = OM_uint32()

        name = gss_name_t()
        lifetime = OM_uint32()
        usage = gss_cred_usage_t()

        retval = gss_inquire_cred(
            byref(minor_status),
            self._cred,
            byref(name) if get_name else None,
            byref(lifetime) if get_lifetime else None,
            byref(usage) if get_usage else None,
            None
        )

        try:
            if GSS_ERROR(retval):
                raise GSSException(retval, minor_status)
            if get_name:
                nameobj = BaseName()
                nameobj._name = name
            return (
                nameobj if get_name else None,
                lifetime.value if get_lifetime else None,
                usage.value if get_usage else None
            )

        except:
            if name:
                gss_release_name(byref(minor_status), byref(name))
            raise

    def _release(self):
        if self._cred:
            minor_status = OM_uint32()
            gss_release_cred(byref(minor_status), byref(self._cred))
            self._cred = cast(GSS_C_NO_CREDENTIAL, gss_cred_id_t)

    def __del__(self):
        self._release()


class Credential(BaseCredential):

    def __init__(self, desired_name=GSS_C_NO_NAME, time_req=GSS_C_INDEFINITE,
                 desired_mechs=GSS_C_NO_OID_SET, cred_usage=GSS_C_BOTH):
        super(Credential, self).__init__()
        minor_status = OM_uint32()

        if hasattr(desired_name, '_name'):
            desired_name = desired_name._name
        else:
            desired_name = cast(desired_name, gss_name_t)

        if hasattr(desired_mechs, '_oid_set'):
            desired_mechs = desired_mechs._oid_set
        else:
            desired_mechs = cast(desired_mechs, gss_OID_set)

        actual_mechs = gss_OID_set()
        time_rec = c_uint()

        retval = gss_acquire_cred(
            byref(minor_status),
            desired_name,
            time_req,
            desired_mechs,
            cred_usage,
            byref(self._cred),
            byref(actual_mechs),
            byref(time_rec)
        )
        try:
            if GSS_ERROR(retval):
                raise GSSException(retval, minor_status)

            self._mechs = OIDSet(actual_mechs)
            return self
        except:
            if actual_mechs:
                gss_release_oid_set(byref(minor_status), byref(actual_mechs))
            self._release()
            raise
