from __future__ import absolute_import

from ctypes import cast, byref, c_uint

from .gssapi_h import (
    GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_BOTH,
    GSS_ERROR,
    OM_uint32, gss_cred_id_t, gss_name_t, gss_OID_set, gss_cred_usage_t,
    gss_acquire_cred,
    gss_release_cred, gss_release_oid_set
)
from .error import GSSException
from .names import Name
from .oids import OIDSet


class Credential(object):
    """Wraps a GSS credential handle (gss_cred_id_t)"""

    def __init__(self, desired_name=GSS_C_NO_NAME, time_req=GSS_C_INDEFINITE,
        desired_mechs=GSS_C_NO_OID_SET, cred_usage=GSS_C_BOTH):
        super(Credential, self).__init__()
        self._cred = gss_cred_id_t()

        minor_status = OM_uint32()

        if isinstance(desired_name, Name):
            desired_name = desired_name._name
        else:
            desired_name = cast(desired_name, gss_name_t)

        if isinstance(desired_mechs, OIDSet):
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
        except:
            if self._cred:
                gss_release_cred(byref(minor_status), byref(self._cred))
            if actual_mechs:
                gss_release_oid_set(byref(minor_status), byref(actual_mechs))
            raise

        # TODO: expiry time
