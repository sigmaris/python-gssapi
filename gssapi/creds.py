from __future__ import absolute_import

from ctypes import cast, byref, c_char_p, c_void_p, string_at

from .gssapi_h import (
    GSS_C_NO_CREDENTIAL, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_BOTH,
    GSS_S_COMPLETE,
    OM_uint32, gss_cred_id_t,
    gss_init_sec_context, gss_accept_sec_context, gss_delete_sec_context, gss_release_buffer,
    gss_release_cred, gss_release_name
)
from .error import GSSException, GSSMechException
from .names import MechName


class Credential(object):
    """Wraps a GSS credential handle (gss_cred_id_t)"""

    def __init__(self, desired_name=GSS_C_NO_NAME, time_req=GSS_C_INDEFINITE,
        desired_mechs=GSS_C_NO_OID_SET, cred_usage=GSS_C_BOTH):
        super(Credential, self).__init__()
