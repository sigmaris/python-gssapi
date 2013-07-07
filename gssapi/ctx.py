from __future__ import absolute_import

from ctypes import cast, byref, c_char_p, c_void_p, string_at, c_int

from .gssapi_h import (
    GSS_C_NO_CREDENTIAL, GSS_C_NO_OID, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, GSS_C_TRANS_FLAG,
    GSS_C_INTEG_FLAG, GSS_C_CONF_FLAG, GSS_C_PROT_READY_FLAG, GSS_C_QOP_DEFAULT, GSS_S_CONTINUE_NEEDED,
    GSS_ERROR,
    OM_uint32, gss_OID, gss_buffer_desc, gss_buffer_t, gss_ctx_id_t, gss_name_t, gss_cred_id_t,
    gss_qop_t, gss_channel_bindings_t,
    gss_init_sec_context, gss_accept_sec_context, gss_import_sec_context, gss_export_sec_context,
    gss_inquire_context, gss_get_mic, gss_verify_mic, gss_wrap, gss_unwrap, gss_wrap_size_limit,
    gss_delete_sec_context, gss_release_buffer,
    gss_release_cred, gss_release_name
)
from .error import GSSCException, GSSException, GSSMechException
from .names import MechName, BaseName
from .oids import OID


class Context(object):
    def __init__(self):
        self._ctx = gss_ctx_id_t()
        self._reset_flags()

    def _reset_flags(self):
        self.established = False
        self.flags = 0
        self.mech_type = None

    def step(self, input_token):
        raise NotImplementedError()

    def get_mic(self, message, qop_req=GSS_C_QOP_DEFAULT):
        if not (self.flags & GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if not (self.established or (self.flags & GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = OM_uint32()
        output_token_buffer = gss_buffer_desc()
        message_buffer = gss_buffer_desc()
        message_buffer.length = len(message)
        message_buffer.value = cast(c_char_p(message), c_void_p)
        retval = gss_get_mic(
            byref(minor_status),
            byref(self._ctx),
            gss_qop_t(qop_req),
            byref(message),
            byref(output_token_buffer)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and self.mech_type:
                    raise GSSMechException(retval, minor_status, self.mech_type)
                else:
                    raise GSSCException(retval, minor_status)

            output_token = string_at(output_token_buffer.value, output_token_buffer.length)
            return output_token
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))

    def verify_mic(self, message, mic):
        if not (self.flags & GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if not (self.established or (self.flags & GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = OM_uint32()
        message_buffer = gss_buffer_desc()
        message_buffer.length = len(message)
        message_buffer.value = cast(c_char_p(message), c_void_p)
        mic_buffer = gss_buffer_desc()
        mic_buffer.length = len(mic)
        mic_buffer.value = cast(c_char_p(mic), c_void_p)
        qop_state = gss_qop_t()

        retval = gss_verify_mic(
            byref(minor_status),
            byref(self._ctx),
            byref(message_buffer),
            byref(mic_buffer),
            byref(qop_state)
        )
        if GSS_ERROR(retval):
            if minor_status and self.mech_type:
                raise GSSMechException(retval, minor_status, self.mech_type)
            else:
                raise GSSCException(retval, minor_status)
        return qop_state.value

    def wrap(self, message, conf_req=True, qop_req=GSS_C_QOP_DEFAULT):
        if not (self.flags & GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if (conf_req and not (self.flags & GSS_C_CONF_FLAG)):
            raise GSSException("No confidentiality protection negotiated.")
        if not (self.established or (self.flags & GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = OM_uint32()
        output_token_buffer = gss_buffer_desc()
        message_buffer = gss_buffer_desc()
        message_buffer.length = len(message)
        message_buffer.value = cast(c_char_p(message), c_void_p)
        conf_state = c_int()

        retval = gss_wrap(
            byref(minor_status),
            byref(self._ctx),
            c_int(conf_req),
            gss_qop_t(qop_req),
            byref(message_buffer),
            byref(conf_state),
            byref(output_token_buffer)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and self.mech_type:
                    raise GSSMechException(retval, minor_status, self.mech_type)
                else:
                    raise GSSCException(retval, minor_status)

            output_token = string_at(output_token_buffer.value, output_token_buffer.length)
            return (output_token, bool(conf_state.value))
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))

    def unwrap(self, message):
        if not (self.flags & GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if not (self.established or (self.flags & GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = OM_uint32()
        output_buffer = gss_buffer_desc()
        message_buffer = gss_buffer_desc()
        message_buffer.length = len(message)
        message_buffer.value = cast(c_char_p(message), c_void_p)
        conf_state = c_int()
        qop_state = gss_qop_t()

        retval = gss_unwrap(
            byref(minor_status),
            byref(self._ctx),
            byref(message_buffer),
            byref(output_buffer),
            byref(conf_state),
            byref(qop_state)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and self.mech_type:
                    raise GSSMechException(retval, minor_status, self.mech_type)
                else:
                    raise GSSCException(retval, minor_status)

            output = string_at(output_buffer.value, output_buffer.length)
            return (output, bool(conf_state.value), qop_state.value)
        finally:
            if output_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_buffer))

    def get_wrap_size_limit(self, output_size, conf_req=True, qop_req=GSS_C_QOP_DEFAULT):
        minor_status = OM_uint32()
        req_output_size = OM_uint32(output_size)
        max_input_size = OM_uint32()
        retval = gss_wrap_size_limit(
            byref(minor_status),
            byref(self._ctx),
            c_int(conf_req),
            gss_qop_t(qop_req),
            req_output_size,
            byref(max_input_size)
        )
        if GSS_ERROR(retval):
            if minor_status and self.mech_type:
                raise GSSMechException(retval, minor_status, self.mech_type)
            else:
                raise GSSCException(retval, minor_status)

        return max_input_size.value

    def export(self):
        if not (self.flags & GSS_C_TRANS_FLAG):
            raise GSSException("Context is not transferable.")
        if not self._ctx:
            raise GSSException("Can't export empty/invalid context.")

        minor_status = OM_uint32()
        output_token_buffer = gss_buffer_desc()
        retval = gss_export_sec_context(
            byref(minor_status),
            byref(self._ctx),
            byref(output_token_buffer)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and self.mech_type:
                    raise GSSMechException(retval, minor_status, self.mech_type)
                else:
                    raise GSSCException(retval, minor_status)

            exported_token = string_at(output_token_buffer.value, output_token_buffer.length)
            self._ctx = gss_ctx_id_t()
            return exported_token
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))

    @staticmethod
    def imprt(import_token):
        minor_status = OM_uint32()
        import_token_buffer = gss_buffer_desc()
        import_token_buffer.length = len(import_token)
        import_token_buffer.value = cast(c_char_p(import_token), c_void_p)
        new_context = gss_ctx_id_t()
        retval = gss_import_sec_context(
            byref(minor_status),
            byref(import_token_buffer),
            byref(new_context)
        )
        try:
            if GSS_ERROR(retval):
                raise GSSCException(retval, minor_status)

            locally_initiated = c_int()
            established = c_int()
            src_name = BaseName()
            target_name = BaseName()
            mech_type = gss_OID()
            flags = OM_uint32()
            retval = gss_inquire_context(
                byref(minor_status),
                new_context,
                byref(src_name._name),
                byref(target_name._name),
                None,  # lifetime_rec
                byref(mech_type),
                byref(flags),
                byref(locally_initiated),
                byref(established)
            )
            if GSS_ERROR(retval):
                raise GSSCException(retval, minor_status)

            mech = OID(mech_type.contents) if mech_type else None

            if locally_initiated:
                new_context_obj = InitContext(target_name, mech_type=mech)
                new_context_obj.flags = flags.value
                new_context_obj.established = bool(established)
            else:
                new_context_obj = AcceptContext()
                new_context_obj.flags = flags.value
                new_context_obj.established = bool(established)
                new_context_obj.peer_name = src_name
            return new_context_obj
        except:
            if new_context:
                gss_delete_sec_context(
                    byref(minor_status),
                    byref(new_context),
                    cast(GSS_C_NO_BUFFER, gss_buffer_t)
                )
            raise

    @property
    def lifetime(self):
        minor_status = OM_uint32()
        lifetime_rec = OM_uint32()

        retval = gss_inquire_context(
            byref(minor_status),
            self._ctx,
            None,  # src_name
            None,  # target_name
            byref(lifetime_rec),
            None,  # mech_type
            None,  # ctx_flags
            None,  # locally_initiated
            None   # established
        )
        if GSS_ERROR(retval):
            raise GSSCException(retval, minor_status)
        return lifetime_rec.value

    def delete(self):
        if not self._ctx:
            raise GSSException("Can't delete invalid context")
        return self._release()

    def _release(self):
        if self._ctx:
            minor_status = OM_uint32()
            output_token_buffer = gss_buffer_desc()

            # This ought to set self._ctx to GSS_C_NO_CONTEXT
            retval = gss_delete_sec_context(
                byref(minor_status),
                byref(self._ctx),
                byref(output_token_buffer)
            )
            try:
                if GSS_ERROR(retval):
                    if minor_status and self.mech_type:
                        raise GSSMechException(retval, minor_status, self.mech_type)
                    else:
                        raise GSSCException(retval, minor_status)

                return string_at(output_token_buffer.value, output_token_buffer.length)
            finally:
                self._reset_flags()
                if output_token_buffer.length != 0:
                    gss_release_buffer(byref(minor_status), byref(output_token_buffer))

    def __del__(self):
        self._release()


class InitContext(Context):

    def __init__(self, target_name, cred=GSS_C_NO_CREDENTIAL, mech_type=None, req_flags=0, time_req=0,
                 input_chan_bindings=GSS_C_NO_CHANNEL_BINDINGS):
        super(InitContext, self).__init__()
        self._target_name = target_name

        if hasattr(cred, '_cred'):
            self._cred = cred._cred
            self._cred_object = cred
        else:
            self._cred = cast(cred, gss_cred_id_t)

        self._desired_mech = mech_type
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

        if self._desired_mech:
            desired_mech = byref(self._desired_mech._oid)
        else:
            desired_mech = cast(GSS_C_NO_OID, gss_OID)

        actual_mech = gss_OID()
        output_token_buffer = gss_buffer_desc()
        actual_flags = OM_uint32()
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
            byref(actual_flags),
            byref(actual_time)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and actual_mech:
                    raise GSSMechException(retval, minor_status, actual_mech)
                else:
                    raise GSSCException(retval, minor_status)

            self.established = not (retval & GSS_S_CONTINUE_NEEDED)
            self.flags = actual_flags.value

            if actual_mech:
                self.mech_type = OID(actual_mech.contents)

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
                self._reset_flags()
            raise
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))


class AcceptContext(Context):

    def __init__(self, cred=GSS_C_NO_CREDENTIAL, input_chan_bindings=GSS_C_NO_CHANNEL_BINDINGS):
        super(AcceptContext, self).__init__()

        if hasattr(cred, '_cred'):
            self._cred = cred._cred
            self._cred_object = cred
        else:
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
        actual_flags = OM_uint32()
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
            byref(actual_flags),
            byref(time_rec),
            byref(delegated_cred_handle)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and mech_type:
                    raise GSSMechException(retval, minor_status, mech_type)
                else:
                    raise GSSCException(retval, minor_status)

            self.established = not (retval & GSS_S_CONTINUE_NEEDED)
            self.flags = actual_flags.value

            if mech_type:
                self.mech_type = OID(mech_type.contents)

                if src_name:
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
                self._reset_flags()
            if src_name:
                gss_release_name(byref(minor_status), byref(src_name))
            raise
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))
            if delegated_cred_handle:
                gss_release_cred(byref(minor_status), byref(delegated_cred_handle))
