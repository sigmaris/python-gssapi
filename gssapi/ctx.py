from __future__ import absolute_import

from ctypes import cast, byref, c_char_p, c_void_p, string_at, c_int
import functools
import operator

from .headers.gssapi_h import (
    GSS_C_NO_CREDENTIAL, GSS_C_NO_OID, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
    GSS_C_INTEG_FLAG, GSS_C_CONF_FLAG, GSS_C_PROT_READY_FLAG, GSS_C_QOP_DEFAULT, GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_ANON_FLAG, GSS_C_DELEG_FLAG, GSS_C_TRANS_FLAG,
    GSS_S_CONTINUE_NEEDED, GSS_ERROR,
    OM_uint32, gss_OID, gss_buffer_desc, gss_buffer_t, gss_ctx_id_t, gss_name_t, gss_cred_id_t,
    gss_qop_t, gss_channel_bindings_t,
    gss_init_sec_context, gss_accept_sec_context, gss_import_sec_context, gss_export_sec_context,
    gss_inquire_context, gss_get_mic, gss_verify_mic, gss_wrap, gss_unwrap, gss_wrap_size_limit,
    gss_delete_sec_context, gss_release_buffer,
    gss_release_cred, gss_release_name
)
from .error import GSSCException, GSSException, GSSMechException
from .names import MechName, Name
from .oids import OID
from .creds import Credential


class Context(object):
    """
    Represents a GSSAPI security context. This class manages establishing the context with a peer,
    and optionally can provide integrity (signing) and confidentiality (encryption) protection for
    messages exchanged with the peer.

    This class is not particularly useful in itself, but holds common functionality for all types
    of context. To use a context as the initiator or acceptor, :class:`InitContext` or
    :class:`AcceptContext` should be used, respectively.

    .. py:attribute:: established

        If this context has been established (via the exchange of tokens with a peer), this will be
        True. Otherwise it will be False.

    .. py:attribute:: mech_type

        If this context has been established, this will be a :class:`~gssapi.oids.OID` identifying
        the mechanism used to establish the security context. Otherwise it will be None.

    .. py:attribute:: flags

        This is an integer which is the bitwise-OR of all the flags representing features that have
        been negotiated on an established connection. It is recommended to check the
        :attr:`integrity_negotiated`, :attr:`confidentiality_negotiated`, etc, properties than
        doing bitwise comparisons on this attribute.
    """
    def __init__(self):
        self._ctx = gss_ctx_id_t()
        self._reset_flags()

    def _reset_flags(self):
        self.established = False
        self.flags = 0
        self.mech_type = None

    def step(self, input_token):
        raise NotImplementedError()

    @property
    def integrity_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if integrity protection (signing) has been negotiated in this context, False
        otherwise. If this property is True, you can use :meth:`get_mic` to sign messages with a
        message integrity code (MIC), which the peer application can verify.
        """
        return (
            self.flags & GSS_C_INTEG_FLAG
        ) and (
            self.established or (self.flags & GSS_C_PROT_READY_FLAG)
        )

    @property
    def confidentiality_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if confidentiality (encryption) has been negotiated in this context, False otherwise.
        If this property is True, you can use :meth:`wrap` with the `conf_req` param set to True to
        encrypt messages sent to the peer application.
        """
        return (
            self.flags & GSS_C_CONF_FLAG
        ) and (
            self.established or (self.flags & GSS_C_PROT_READY_FLAG)
        )

    @property
    def replay_detection_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if the security context can use replay detection for messages protected by
        :meth:`get_mic` and :meth:`wrap`. False if replay detection cannot be used.
        """
        return (
            self.flags & GSS_C_REPLAY_FLAG
        ) and (
            self.established or (self.flags & GSS_C_PROT_READY_FLAG)
        )

    @property
    def sequence_detection_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if the security context can use out-of-sequence message detection for messages
        protected by :meth:`get_mic` and :meth:`wrap`. False if OOS detection cannot be used.
        """
        return (
            self.flags & GSS_C_SEQUENCE_FLAG
        ) and (
            self.established or (self.flags & GSS_C_PROT_READY_FLAG)
        )

    @property
    def mutual_auth_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if mutual authentication was negotiated, False otherwise.
        """
        return bool(self.flags & GSS_C_MUTUAL_FLAG)

    @property
    def initiator_is_anonymous(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if the initiator did not reveal its name to the acceptor, False if the initiator's
        name is revealed and authenticated to the acceptor. If True, the
        :attr:`~AcceptContext.peer_name` property of the :class:`AcceptContext` will be an
        anonymous internal name.
        """
        return bool(self.flags & GSS_C_ANON_FLAG)

    @property
    def is_transferable(self):
        """
        True if the context can be transferred between processes using :meth:`export` and
        :meth:`imprt`, False otherwise.
        """
        return bool(self.flags & GSS_C_TRANS_FLAG)

    def get_mic(self, message, qop_req=GSS_C_QOP_DEFAULT):
        """
        Calculates a cryptographic message integrity code (MIC) over an application message, and
        returns that MIC in a token. This is in contrast to :meth:`wrap` which calculates a MIC
        over a message, optionally encrypts it and returns the original message and the MIC packed
        into a single token. The peer application can then verify the MIC to ensure the associated
        message has not been changed in transit.

        :param message: The message to calculate a MIC for
        :type message: bytes
        :returns: A MIC for the message calculated using this security context's cryptographic keys
        :rtype: bytes
        """
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
            self._ctx,
            gss_qop_t(qop_req),
            byref(message_buffer),
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
        """
        Takes a message integrity code (MIC) that has been generated by the peer application for a
        given message, and verifies it against a message, using this security context's
        cryptographic keys.

        :param message: The message the MIC was calculated for
        :type message: bytes
        :param mic: The MIC calculated by the peer
        :type mic: bytes
        :returns: the quality of protection (qop_state)
        :raises: GSSException if :attr:`integrity_negotiated` is false, or if the verification
            fails indicating the message was modified
        """
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
            self._ctx,
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
        """
        Wraps a message with a message integrity code, and if `conf_req` is True, encrypts the
        message. The message can be decrypted and the MIC verified by the peer by passing the
        token returned from this method to :meth:`unwrap` on the peer's side.

        :param message: The message to wrap
        :type message: bytes
        :param conf_req: Whether to require confidentiality (encryption)
        :type conf_req: bool
        :returns: the wrapped message in a token suitable for passing to :meth:`unwrap`
        :rtype: bytes
        :raises: GSSException if integrity protection is not available
            (:attr:`integrity_negotiated` is False), or if the `conf_req` parameter is True and
            confidentiality protection is not available
            (:attr:`confidentiality_negotiated` is False)
        """
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
            self._ctx,
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
            if conf_req and not conf_state.value:
                raise GSSException("No confidentiality protection.")
            return output_token
        finally:
            if output_token_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_token_buffer))

    def unwrap(self, message, conf_req=True, qop_req=None):
        """
        Takes a token that has been generated by the peer application with :meth:`wrap`, verifies
        and optionally decrypts it, using this security context's cryptographic keys.

        :param message: The wrapped message token
        :type message: bytes
        :param conf_req: Whether to require confidentiality (encryption)
        :type conf_req: bool
        :returns: the verified and decrypted message
        :raises: GSSException if :attr:`integrity_negotiated` is false, or if the verification or
            decryption fails, if the message was modified, or if confidentiality was required
            (`conf_req` was True) but the message did not have confidentiality protection applied
            (was not encrypted).
        """
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
            self._ctx,
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
            if conf_req and not conf_state.value:
                raise GSSException("No confidentiality protection.")
            if qop_req is not None and qop_req != qop_state.value:
                raise GSSException("QOP {0} does not match required value {1}.".format(qop_state.value, qop_req))
            return output
        finally:
            if output_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_buffer))

    def get_wrap_size_limit(self, output_size, conf_req=True, qop_req=GSS_C_QOP_DEFAULT):
        """
        Calculates the maximum size of message that can be fed to :meth:`wrap` so that the size of
        the resulting wrapped token (message plus wrapping overhead) is no more than a given
        maximum output size.

        :param output_size: The maximum output size (in bytes) of a wrapped token
        :type output_size: int
        :param conf_req: Whether to calculate the wrapping overhead for confidentiality protection
            (if True) or just integrity protection (if False).
        :type conf_req: bool
        :returns: The maximum input size (in bytes) of message that can be passed to :meth:`wrap`
        :rtype: int
        """

        minor_status = OM_uint32()
        req_output_size = OM_uint32(output_size)
        max_input_size = OM_uint32()
        retval = gss_wrap_size_limit(
            byref(minor_status),
            self._ctx,
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
        """
        This method deactivates the security context for the calling process and returns an
        interprocess token which, when passed to :meth:`imprt` in another process, will re-activate
        the context in the second process. Only a single instantiation of a given context may be
        active at any one time; attempting to access this security context after calling
        :meth:`export` will fail. This method can only be used on a valid context where
        :attr:`is_transferable` is True.

        :returns: a token which represents this security context
        :rtype: bytes
        """
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
        """
        This is the corresponding method to :meth:`export`, used to import a saved context token
        from another process into this one and construct a :class:`Context` object from it.

        :param import_token: a token obtained from the :meth:`export` of another context
        :type import_token: bytes
        :returns: a Context object created from the imported token
        :rtype: :class:`Context`
        """

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
            src_name = Name(gss_name_t())
            target_name = Name(gss_name_t())
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
                new_context_obj._ctx = new_context
                new_context_obj.mech_type = mech
                new_context_obj.flags = flags.value
                new_context_obj.established = bool(established)
            else:
                new_context_obj = AcceptContext()
                new_context_obj._ctx = new_context
                new_context_obj.mech_type = mech
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
        """
        The lifetime of the context in seconds (only valid after :meth:`step` has been called). If
        the context does not have a time limit on its validity, this will be
        :const:`gssapi.C_INDEFINITE`
        """

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
        """
        Delete a security context. This method will delete the local data structures associated
        with the specified security context, and may return an output token, which when passed to
        :meth:`process_context_token` on the peer will instruct it to do likewise.

        After this method is called, this security context will become invalid and should not be
        used in any way.

        :returns: An output token if one should be passed to :meth:`process_context_token` on the
            peer, otherwise an empty bytestring.
        :rtype: bytes
        """

        if not self._ctx:
            raise GSSException("Can't delete invalid context")
        return self._release()

    def _release(self):
        if hasattr(self, '_ctx') and self._ctx:
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
    """
    An instance of this class can be used to initiate a secure context between two applications.
    The application using `InitContext` must specify the :class:`~gssapi.names.Name` of the
    acceptor it wants to connect to, and send the first token it obtains from :meth:`step` to the
    acceptor. The acceptor should then respond and proceed with the establishment of the security
    context.

    :param peer_name: The name of the acceptor
    :type peer_name: :class:`~gssapi.names.Name`
    :param cred: A credential to use to identify the initiator. If not provided, the default
        initiator credential will be used.
    :type cred: :class:`~gssapi.creds.Credential`
    :param mech_type: The mechanism to use. If not specified, an implementation specific default
        will be used.
    :type mech_type: :class:`~gssapi.oids.OID`
    :param req_flags: a list of requested flags, any combination of :const:`gssapi.C_DELEG_FLAG`,
        :const:`gssapi.C_MUTUAL_FLAG`, :const:`gssapi.C_REPLAY_FLAG`,
        :const:`gssapi.C_SEQUENCE_FLAG`, :const:`gssapi.C_CONF_FLAG`, :const:`gssapi.C_INTEG_FLAG`
        and :const:`gssapi.C_ANON_FLAG` can be used.
    :type req_flags: iterable
    :param time_req: the number of seconds for which the context should be valid. If not provided,
        a default lifetime will be used.
    :type time_req: int

    """

    def __init__(self, peer_name, cred=GSS_C_NO_CREDENTIAL, mech_type=None, req_flags=(), time_req=0,
                 input_chan_bindings=GSS_C_NO_CHANNEL_BINDINGS):
        super(InitContext, self).__init__()
        self.peer_name = peer_name

        if hasattr(cred, '_cred'):
            self._cred = cred._cred
            self._cred_object = cred
        else:
            self._cred = cast(cred, gss_cred_id_t)

        self._desired_mech = mech_type
        self._req_flags = functools.reduce(operator.or_, req_flags, 0)
        self._time_req = time_req
        self._input_chan_bindings = cast(input_chan_bindings, gss_channel_bindings_t)

    def step(self, input_token=None):
        """Performs a step to establish the context as an initiator.

        This method should be called in a loop and fed input tokens
        from the acceptor, and its output tokens should be sent to the
        acceptor, until this context's established attribute is True.

        :param input_token: The input token from the acceptor (omit this param on the first step).
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
            self.peer_name._name,
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
            if output_token_buffer.length != 0:
                out_token = string_at(output_token_buffer.value, output_token_buffer.length)
            else:
                out_token = None

            if GSS_ERROR(retval):
                if minor_status and actual_mech:
                    raise GSSMechException(retval, minor_status, actual_mech, out_token)
                else:
                    raise GSSCException(retval, minor_status, out_token)

            self.established = not (retval & GSS_S_CONTINUE_NEEDED)
            self.flags = actual_flags.value

            if actual_mech:
                self.mech_type = OID(actual_mech.contents)

            return out_token
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
    """
    This class is used to accept a connection from an initiator and establish and manage a security
    context on the acceptor side. The initiator is normally authenticated as part of the context
    establishment process, though some mechanisms support anonymous peers.

    :param cred: The credential to use for the acceptor. Pass :data:`C_NO_CREDENTIAL` to use
        the default acceptor credentials (e.g. any principal in the default keytab, when the
        Kerberos mechanism is used).
    :type cred: :class:`~gssapi.creds.Credential`

    .. py:attribute:: delegated_cred

        If the initiator delegated a credential to this acceptor, this will be
        :class:`~gssapi.creds.Credential` object containing the delegated credential. Otherwise
        it will be set to None.

    .. py:attribute:: peer_name

        If this context has authenticated an initiator, this will be a
        :class:`~gssapi.names.MechName` object representing the initiator. Otherwise it will be set
        to None.
    """

    def __init__(self, cred=GSS_C_NO_CREDENTIAL, input_chan_bindings=GSS_C_NO_CHANNEL_BINDINGS):
        super(AcceptContext, self).__init__()

        if hasattr(cred, '_cred'):
            self._cred = cred._cred
            self._cred_object = cred
        else:
            self._cred = cast(cred, gss_cred_id_t)
        self.delegated_cred = None
        self.peer_name = None

        self._input_chan_bindings = cast(input_chan_bindings, gss_channel_bindings_t)

    def step(self, input_token):
        """Performs a step to establish the context as an acceptor.

        This method should be called in a loop and fed input tokens
        from the initiator, and its output tokens should be sent to the
        initiator, until this context's established attribute is True.

        :param input_token: The input token from the initiator (required).
        :type input_token: bytes
        :returns: either a byte string with the next token to send to the initiator,
            or None if there is no further token to send to the initiator.
        :raises: GSSException
        """
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
            if output_token_buffer.length != 0:
                out_token = string_at(output_token_buffer.value, output_token_buffer.length)
            else:
                out_token = None

            if GSS_ERROR(retval):
                if minor_status and mech_type:
                    raise GSSMechException(retval, minor_status, mech_type, out_token)
                else:
                    raise GSSCException(retval, minor_status, out_token)

            self.established = not (retval & GSS_S_CONTINUE_NEEDED)
            self.flags = actual_flags.value

            if (self.flags & GSS_C_DELEG_FLAG):
                self.delegated_cred = Credential(delegated_cred_handle)

            if mech_type:
                self.mech_type = OID(mech_type.contents)

                if src_name:
                    self.peer_name = MechName(src_name, mech_type)

            return out_token
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
            # if self.delegated_cred is present, it will handle gss_release_cred:
            if delegated_cred_handle and not self.delegated_cred:
                gss_release_cred(byref(minor_status), byref(delegated_cred_handle))
