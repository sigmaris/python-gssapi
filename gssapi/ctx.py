from __future__ import absolute_import

from ctypes import cast, byref, c_char_p, c_void_p, string_at

from .gssapi_h import (
    GSS_C_NO_CREDENTIAL, GSS_C_NO_OID, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
    GSS_S_CONTINUE_NEEDED,
    GSS_ERROR,
    OM_uint32, gss_OID, gss_buffer_desc, gss_buffer_t, gss_ctx_id_t, gss_name_t, gss_cred_id_t,
    gss_channel_bindings_t,
    gss_init_sec_context, gss_accept_sec_context, gss_delete_sec_context, gss_release_buffer,
    gss_release_cred, gss_release_name
)
from .error import GSSException, GSSMechException
from .names import MechName


class Context(object):
    def __init__(self):
        self._ctx = gss_ctx_id_t()
        self.established = False


class InitContext(Context):

    def __init__(self, target_name, cred=GSS_C_NO_CREDENTIAL, mech_type=None, req_flags=0, time_req=0,
                 input_chan_bindings=GSS_C_NO_CHANNEL_BINDINGS):
        super(InitContext, self).__init__()
        self._target_name = target_name
        self._cred = cast(cred, gss_cred_id_t)
        self._mech_type = mech_type
        self._req_flags = req_flags
        self._time_req = time_req
        self._input_chan_bindings = cast(input_chan_bindings, gss_channel_bindings_t)

    def step(self, input_token=None):
        """Performs a step to establish the context as an initiator.

        This method should be called in a loop and fed input tokens
        from the acceptor, and its output tokens should be sent to the
        acceptor, until this context's established attribute is True.

        :param input_token: The input token from the acceptor (omit this on the first step).
        :type input_token: bytes.
        :returns: either a byte string with the next token to send to the acceptor,
            or None if there is no further token to send to the acceptor.
        :raises: GSSException
        """

        minor_status = OM_uint32()

        if input_token:
            input_token_buffer = gss_buffer_desc()
            input_token_buffer.length = len(input_token)
            input_token_buffer.value = cast(c_char_p(input_token), c_void_p)
            input_token_buffer_ptr = byref(input_token_buffer)
        else:
            input_token_buffer_ptr = cast(GSS_C_NO_BUFFER, gss_buffer_t)

        if self._mech_type:
            desired_mech = byref(self._mech_type._oid)
        else:
            desired_mech = cast(GSS_C_NO_OID, gss_OID)

        actual_mech = gss_OID()
        output_token_buffer = gss_buffer_desc()
        actual_services = OM_uint32()
        actual_time = OM_uint32()

        retval = gss_init_sec_context(
            byref(minor_status),
            self._cred,
            byref(self._ctx),
            self._target_name._name,
            desired_mech,
            self._req_flags,
            self._time_req,
            self._input_chan_bindings,
            input_token_buffer_ptr,
            byref(actual_mech),
            byref(output_token_buffer),
            byref(actual_services),
            byref(actual_time)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and actual_mech:
                    raise GSSMechException(retval, minor_status, actual_mech)
                else:
                    raise GSSException(retval, minor_status)

            self.established = not (retval & GSS_S_CONTINUE_NEEDED)

            if output_token_buffer.length != 0:
                return string_at(output_token_buffer.value, output_token_buffer.length)
            else:
                return None
        except:
            if self._ctx:
                gss_delete_sec_context(
                    byref(minor_status),
                    byref(self._ctx),
                    cast(GSS_C_NO_BUFFER, gss_buffer_t)
                )
            raise
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))


class AcceptContext(Context):

    def __init__(self, cred=GSS_C_NO_CREDENTIAL, input_chan_bindings=GSS_C_NO_CHANNEL_BINDINGS):
        super(AcceptContext, self).__init__()
        self._cred = cast(cred, gss_cred_id_t)
        self._input_chan_bindings = cast(input_chan_bindings, gss_channel_bindings_t)

    def step(self, input_token):
        minor_status = OM_uint32()
        input_token_buffer = gss_buffer_desc()
        input_token_buffer.length = len(input_token)
        input_token_buffer.value = cast(c_char_p(input_token), c_void_p)
        mech_type = gss_OID()
        output_token_buffer = gss_buffer_desc()
        src_name = gss_name_t()
        ret_flags = OM_uint32()
        time_rec = OM_uint32()
        delegated_cred_handle = gss_cred_id_t()

        retval = gss_accept_sec_context(
            byref(minor_status),
            byref(self._ctx),
            self._cred,
            byref(input_token_buffer),
            self._input_chan_bindings,
            byref(src_name),
            byref(mech_type),
            byref(output_token_buffer),
            byref(ret_flags),
            byref(time_rec),
            byref(delegated_cred_handle)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and mech_type:
                    raise GSSMechException(retval, minor_status, mech_type)
                else:
                    raise GSSException(retval, minor_status)

            self.established = not (retval & GSS_S_CONTINUE_NEEDED)

            if src_name and mech_type:
                self.peer_name = MechName(src_name, mech_type)

            if output_token_buffer.length != 0:
                return string_at(output_token_buffer.value, output_token_buffer.length)
            else:
                return None
        except:
            if self._ctx:
                gss_delete_sec_context(
                    byref(minor_status),
                    byref(self._ctx),
                    cast(GSS_C_NO_BUFFER, gss_buffer_t)
                )
            if src_name:
                gss_release_name(byref(minor_status), byref(src_name))
            raise
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))
            if delegated_cred_handle:
                gss_release_cred(byref(minor_status), byref(delegated_cred_handle))
