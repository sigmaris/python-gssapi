from __future__ import absolute_import

from ctypes import cast, byref, c_char_p, c_void_p

from .gssapi_h import (
    GSS_C_NO_CREDENTIAL, GSS_C_NO_OID, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
    GSS_S_COMPLETE,
    OM_uint32, gss_OID, gss_OID_desc, gss_buffer_desc,
    gss_init_sec_context, gss_accept_sec_context
)
from . import GSSException


class Context(object):
    def __init__(self):
        self._ctx = gss_ctx_id_t()


class InitContext(Context):

    def __init__(self, target_name, cred=GSS_C_NO_CREDENTIAL, mech_type=None, req_flags=0, time_req=0,
                 input_chan_bindings=GSS_C_NO_CHANNEL_BINDINGS):
        super(InitContext, self).__init__()
        self._target_name = target_name
        self._cred = cred
        self._mech_type = mech_type,
        self._req_flags = req_flags,
        self._time_req = time_req
        self._input_chan_bindings = input_chan_bindings
        self._steps = 0

    def step(self, input_token=None):
        minor_status = OM_uint32()

        if input_token:
            input_token_buffer = gss_buffer_desc()
            input_token_buffer.length = len(input_token)
            input_token_buffer.value = cast(c_char_p(input_token), c_void_p)
        else:
            input_token_buffer = GSS_C_NO_BUFFER

        if self._mech_type:
            desired_mech = self._mech_type._oid
        else:
            desired_mech = GSS_C_NO_OID

        actual_mech = gss_OID()
        output_token_buffer = gss_buffer_desc()
        actual_services = OM_uint32()
        actual_time = OM_uint32()

        retval = gss_init_sec_context(
            byref(minor_status), self._cred, byref(self._ctx), self._target_name._name,
            byref(desired_mech), self._req_flags, self._time_req, self._input_chan_bindings,
            byref(input_token_buffer), byref(actual_mech), byref(output_token_buffer),
            byref(actual_services), byref(actual_time)
        )
        try:
            if retval 
        finally:
            if output_token_buffer.length != 0:
                
