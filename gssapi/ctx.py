from __future__ import absolute_import

import functools
import operator

from .bindings import ffi, C, GSS_ERROR, GSS_SUPPLEMENTARY_INFO, _buf_to_str
from .error import GSSException, _exception_for_status
from .names import MechName, Name
from .oids import OID
from .creds import Credential


def _release_gss_ctx_id_t(context):
    if context[0]:
        C.gss_delete_sec_context(
            ffi.new('OM_unit32[1]'),
            context,
            ffi.cast('gss_buffer_t', C.GSS_C_NO_BUFFER)
        )


def _status_bits(retval):
    supplementary_info = GSS_SUPPLEMENTARY_INFO(retval)
    return tuple(
        f for f in (
            C.GSS_S_DUPLICATE_TOKEN, C.GSS_S_OLD_TOKEN, C.GSS_S_UNSEQ_TOKEN, C.GSS_S_GAP_TOKEN
        )
        if f & supplementary_info
    )



class Context(object):
    """
    Represents a GSSAPI security context. This class manages establishing the context with a peer,
    and optionally can provide integrity (signing) and confidentiality (encryption) protection for
    messages exchanged with the peer.

    This class is not particularly useful in itself, but holds common functionality for all types
    of context. To use a context as the initiator or acceptor, create an :class:`InitContext` or
    :class:`AcceptContext`, respectively.

    .. py:attribute:: established

        If this context has been established (via the exchange of tokens with a peer), this will be
        True. Otherwise it will be False.

    .. py:attribute:: mech_type

        If this context has been established, this will be a :class:`~gssapi.oids.OID` identifying
        the mechanism used to establish the security context. Otherwise it will be None.

    .. py:attribute:: flags

        This is an integer which is the bitwise-OR of all the flags representing features that have
        been negotiated on an established connection. It is recommended to check the properties
        :attr:`integrity_negotiated`, :attr:`confidentiality_negotiated`, etc, instead of doing
        bitwise comparisons on this attribute.
    """
    def __init__(self):
        self._ctx = ffi.new('gss_ctx_id_t[1]')
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
            self.flags & C.GSS_C_INTEG_FLAG
        ) and (
            self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)
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
            self.flags & C.GSS_C_CONF_FLAG
        ) and (
            self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)
        )

    @property
    def replay_detection_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if the security context can use replay detection for messages protected by
        :meth:`get_mic` and :meth:`wrap`. False if replay detection cannot be used.
        """
        return (
            self.flags & C.GSS_C_REPLAY_FLAG
        ) and (
            self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)
        )

    @property
    def sequence_detection_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if the security context can use out-of-sequence message detection for messages
        protected by :meth:`get_mic` and :meth:`wrap`. False if OOS detection cannot be used.
        """
        return (
            self.flags & C.GSS_C_SEQUENCE_FLAG
        ) and (
            self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)
        )

    @property
    def mutual_auth_negotiated(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if mutual authentication was negotiated, False otherwise.
        """
        return bool(self.flags & C.GSS_C_MUTUAL_FLAG)

    @property
    def initiator_is_anonymous(self):
        """
        After :meth:`step` has been called, this property will be set to
        True if the initiator did not reveal its name to the acceptor, False if the initiator's
        name is revealed and authenticated to the acceptor. If True, the
        :attr:`~AcceptContext.peer_name` property of the :class:`AcceptContext` will be an
        anonymous internal name.
        """
        return bool(self.flags & C.GSS_C_ANON_FLAG)

    @property
    def is_transferable(self):
        """
        True if the context can be transferred between processes using :meth:`export` and
        :meth:`imprt`, False otherwise.
        """
        return bool(self.flags & C.GSS_C_TRANS_FLAG)

    def get_mic(self, message, qop_req=C.GSS_C_QOP_DEFAULT):
        """
        Calculates a cryptographic message integrity code (MIC) over an application message, and
        returns that MIC in a token. This is in contrast to :meth:`wrap` which calculates a MIC
        over a message, optionally encrypts it and returns the original message and the MIC packed
        into a single token. The peer application can then verify the MIC to ensure the associated
        message has not been changed in transit.

        :param message: The message to calculate a MIC for
        :type message: bytes
        :param qop_req: The quality of protection required. It is recommended to not change this
            from the default as most GSSAPI implementations do not support it.
        :returns: A MIC for the message calculated using this security context's cryptographic keys
        :rtype: bytes
        """
        if not (self.flags & C.GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if not (self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = ffi.new('OM_uint32[1]')
        output_token_buffer = ffi.new('gss_buffer_desc[1]')
        message_buffer = ffi.new('gss_buffer_desc[1]')
        message_buffer[0].length = len(message)
        c_str_message = ffi.new('char[]', message)
        message_buffer[0].value = c_str_message
        retval = C.gss_get_mic(
            minor_status,
            self._ctx[0],
            ffi.cast('gss_qop_t', qop_req),
            message_buffer,
            output_token_buffer
        )
        try:
            if GSS_ERROR(retval):
                if minor_status[0] and self.mech_type:
                    raise _exception_for_status(retval, minor_status[0], self.mech_type)
                else:
                    raise _exception_for_status(retval, minor_status[0])

            output_token = _buf_to_str(output_token_buffer[0])
            return output_token
        finally:
            if output_token_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_token_buffer)

    def verify_mic(self, message, mic, supplementary=False):
        """
        Takes a message integrity code (MIC) that has been generated by the peer application for a
        given message, and verifies it against a message, using this security context's
        cryptographic keys.

        If the `supplementary` parameter is False (default), returns the quality of protection
        only (the ``qop_state`` value). If `supplementary` is True, returns a tuple ``(qop_state,
        supplementary_info)`` where ``supplementary_info`` is a tuple containing zero or more of
        the constants :const:`~gssapi.S_DUPLICATE_TOKEN`, :const:`~gssapi.S_OLD_TOKEN`,
        :const:`~gssapi.S_UNSEQ_TOKEN` and :const:`~gssapi.S_GAP_TOKEN`. The supplementary info
        tells the caller whether a replayed or out-of-sequence message was detected.

        :param message: The message the MIC was calculated for
        :type message: bytes
        :param mic: The MIC calculated by the peer
        :type mic: bytes
        :param supplementary: Whether to also return supplementary info.
        :type supplementary: bool
        :returns: ``qop_state`` if `supplementary` is False, or ``(qop_state,
            supplementary_info)`` if `supplementary` is True.
        :raises: :exc:`~gssapi.error.GSSException` if :attr:`integrity_negotiated` is false, or
            :exc:`~gssapi.error.GSSCException` if the verification fails indicating the message was
            modified.
        """
        if not (self.flags & C.GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if not (self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = ffi.new('OM_uint32[1]')
        message_buffer = ffi.new('gss_buffer_desc[1]')
        message_buffer[0].length = len(message)
        c_str_message = ffi.new('char[]', message)
        message_buffer[0].value = c_str_message
        mic_buffer = ffi.new('gss_buffer_desc[1]')
        mic_buffer[0].length = len(mic)
        c_str_mic = ffi.new('char[]', mic)
        mic_buffer[0].value = c_str_mic
        qop_state = ffi.new('gss_qop_t[1]')

        retval = C.gss_verify_mic(
            minor_status,
            self._ctx[0],
            message_buffer,
            mic_buffer,
            qop_state
        )
        if GSS_ERROR(retval):
            if minor_status[0] and self.mech_type:
                raise _exception_for_status(retval, minor_status[0], self.mech_type)
            else:
                raise _exception_for_status(retval, minor_status[0])
        if supplementary:
            return qop_state[0], _status_bits(retval)
        else:
            return qop_state[0]

    def wrap(self, message, conf_req=True, qop_req=C.GSS_C_QOP_DEFAULT):
        """
        Wraps a message with a message integrity code, and if `conf_req` is True, encrypts the
        message. The message can be decrypted and the MIC verified by the peer by passing the
        token returned from this method to :meth:`unwrap` on the peer's side.

        :param message: The message to wrap
        :type message: bytes
        :param conf_req: Whether to require confidentiality (encryption)
        :type conf_req: bool
        :param qop_req: The quality of protection required. It is recommended to not change this
            from the default as most GSSAPI implementations do not support it.
        :returns: the wrapped message in a token suitable for passing to :meth:`unwrap`
        :rtype: bytes
        :raises: GSSException if integrity protection is not available
            (:attr:`integrity_negotiated` is False), or if the `conf_req` parameter is True and
            confidentiality protection is not available
            (:attr:`confidentiality_negotiated` is False)
        """
        if not (self.flags & C.GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if (conf_req and not (self.flags & C.GSS_C_CONF_FLAG)):
            raise GSSException("No confidentiality protection negotiated.")
        if not (self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = ffi.new('OM_uint32[1]')
        output_token_buffer = ffi.new('gss_buffer_desc[1]')
        message_buffer = ffi.new('gss_buffer_desc[1]')
        message_buffer[0].length = len(message)
        c_str_message = ffi.new('char[]', message)
        message_buffer[0].value = c_str_message
        conf_state = ffi.new('int[1]')

        retval = C.gss_wrap(
            minor_status,
            self._ctx[0],
            ffi.cast('int', conf_req),
            ffi.cast('gss_qop_t', qop_req),
            message_buffer,
            conf_state,
            output_token_buffer
        )
        try:
            if GSS_ERROR(retval):
                if minor_status[0] and self.mech_type:
                    raise _exception_for_status(retval, minor_status[0], self.mech_type)
                else:
                    raise _exception_for_status(retval, minor_status[0])

            output_token = _buf_to_str(output_token_buffer[0])
            if conf_req and not conf_state[0]:
                raise GSSException("No confidentiality protection.")
            return output_token
        finally:
            if output_token_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_token_buffer)

    def unwrap(self, message, conf_req=True, qop_req=None, supplementary=False):
        """
        Takes a token that has been generated by the peer application with :meth:`wrap`, verifies
        and optionally decrypts it, using this security context's cryptographic keys.

        If the `supplementary` parameter is False (default), returns the unwrapped message only.
        If `supplementary` is True, returns a tuple ``(unwrapped_message, supplementary_info)``
        where ``supplementary_info`` is a tuple containing zero or more of the constants
        :const:`~gssapi.S_DUPLICATE_TOKEN`, :const:`~gssapi.S_OLD_TOKEN`,
        :const:`~gssapi.S_UNSEQ_TOKEN` and :const:`~gssapi.S_GAP_TOKEN`. The supplementary info
        tells the caller whether a replayed or out-of-sequence message was detected.

        :param message: The wrapped message token
        :type message: bytes
        :param conf_req: Whether to require confidentiality (encryption)
        :type conf_req: bool
        :param qop_req: The quality of protection required. It is recommended to not change this
            from the default None as most GSSAPI implementations do not support it.
        :param supplementary: Whether to also return supplementary info.
        :type supplementary: bool
        :returns: the verified and decrypted message if `supplementary` is False, or a tuple
            ``(unwrapped_message, supplementary_info)`` if `supplementary` is True.
        :raises: :exc:`~gssapi.error.GSSException` if :attr:`integrity_negotiated` is false, or if
            the verification or decryption fails, if the message was modified, or if
            confidentiality was required (`conf_req` was True) but the message did not have
            confidentiality protection applied (was not encrypted), or if the `qop_req`
            parameter was set and it did not match the QOP applied to the message.
        """
        if not (self.flags & C.GSS_C_INTEG_FLAG):
            raise GSSException("No integrity protection negotiated.")
        if not (self.established or (self.flags & C.GSS_C_PROT_READY_FLAG)):
            raise GSSException("Protection not yet ready.")

        minor_status = ffi.new('OM_uint32[1]')
        output_buffer = ffi.new('gss_buffer_desc[1]')
        message_buffer = ffi.new('gss_buffer_desc[1]')
        message_buffer[0].length = len(message)
        c_str_message = ffi.new('char[]', message)
        message_buffer[0].value = c_str_message
        conf_state = ffi.new('int[1]')
        qop_state = ffi.new('gss_qop_t[1]')

        retval = C.gss_unwrap(
            minor_status,
            self._ctx[0],
            message_buffer,
            output_buffer,
            conf_state,
            qop_state
        )
        try:
            if GSS_ERROR(retval):
                if minor_status[0] and self.mech_type:
                    raise _exception_for_status(retval, minor_status[0], self.mech_type)
                else:
                    raise _exception_for_status(retval, minor_status[0])

            output = _buf_to_str(output_buffer[0])
            if conf_req and not conf_state[0]:
                raise GSSException("No confidentiality protection.")
            if qop_req is not None and qop_req != qop_state[0]:
                raise GSSException("QOP {0} does not match required value {1}.".format(qop_state[0], qop_req))
            if supplementary:
                return output, _status_bits(retval)
            else:
                return output
        finally:
            if output_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_buffer)

    def get_wrap_size_limit(self, output_size, conf_req=True, qop_req=C.GSS_C_QOP_DEFAULT):
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

        minor_status = ffi.new('OM_uint32[1]')
        max_input_size = ffi.new('OM_uint32[1]')
        retval = C.gss_wrap_size_limit(
            minor_status,
            self._ctx[0],
            ffi.cast('int', conf_req),
            ffi.cast('gss_qop_t', qop_req),
            ffi.cast('OM_uint32', output_size),
            max_input_size
        )
        if GSS_ERROR(retval):
            if minor_status[0] and self.mech_type:
                raise _exception_for_status(retval, minor_status[0], self.mech_type)
            else:
                raise _exception_for_status(retval, minor_status[0])

        return max_input_size[0]

    def process_context_token(self, context_token):
        """
        Provides a way to pass an asynchronous token to the security context, outside of the normal
        context-establishment token passing flow. This method is not normally used, but some
        example uses are:

        * when the initiator's context is established successfully but the acceptor's context isn't
          and the acceptor needs to signal to the initiator that the context shouldn't be used.
        * if :meth:`delete` on one peer's context returns a final token that can be passed to the
          other peer to indicate the other peer's context should be torn down as well (though it's
          recommended that :meth:`delete` should return nothing, i.e. this method should not be
          used by GSSAPI mechanisms).

        :param context_token: The context token to pass to the security context
        :type context_token: bytes
        :raises: :exc:`~gssapi.error.DefectiveToken` if consistency checks on the token failed.
            :exc:`~gssapi.error.NoContext` if this context is invalid.
            :exc:`~gssapi.error.GSSException` for any other GSSAPI errors.
        """
        minor_status = ffi.new('OM_uint32[1]')
        context_token_buffer = ffi.new('gss_buffer_desc[1]')
        context_token_buffer[0].length = len(context_token)
        c_str_context_token = ffi.new('char[]', context_token)
        context_token_buffer[0].value = c_str_context_token
        retval = C.gss_process_context_token(
            minor_status,
            self._ctx[0],
            context_token_buffer
        )
        if GSS_ERROR(retval):
            if minor_status[0] and self.mech_type:
                raise _exception_for_status(retval, minor_status[0], self.mech_type)
            else:
                raise _exception_for_status(retval, minor_status[0])

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
        if not (self.flags & C.GSS_C_TRANS_FLAG):
            raise GSSException("Context is not transferable.")
        if not self._ctx:
            raise GSSException("Can't export empty/invalid context.")

        minor_status = ffi.new('OM_uint32[1]')
        output_token_buffer = ffi.new('gss_buffer_desc[1]')
        retval = C.gss_export_sec_context(
            minor_status,
            self._ctx,
            output_token_buffer
        )
        try:
            if GSS_ERROR(retval):
                if minor_status[0] and self.mech_type:
                    raise _exception_for_status(retval, minor_status[0], self.mech_type)
                else:
                    raise _exception_for_status(retval, minor_status[0])

            exported_token = _buf_to_str(output_token_buffer[0])
            # Set our context to a 'blank' context
            self._ctx = ffi.new('gss_ctx_id_t[1]')
            return exported_token
        finally:
            if output_token_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_token_buffer)

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

        minor_status = ffi.new('OM_uint32[1]')
        import_token_buffer = ffi.new('gss_buffer_desc[1]')
        import_token_buffer[0].length = len(import_token)
        c_str_import_token = ffi.new('char[]', import_token)
        import_token_buffer[0].value = c_str_import_token
        new_context = ffi.new('gss_ctx_id_t[1]')
        retval = C.gss_import_sec_context(
            minor_status,
            import_token_buffer,
            new_context
        )
        try:
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])

            src_name = ffi.new('gss_name_t[1]')
            target_name = ffi.new('gss_name_t[1]')
            mech_type = ffi.new('gss_OID[1]')
            flags = ffi.new('OM_uint32[1]')
            locally_initiated = ffi.new('int[1]')
            established = ffi.new('int[1]')
            retval = C.gss_inquire_context(
                minor_status,
                new_context[0],
                src_name,
                target_name,
                ffi.NULL,  # lifetime_rec
                mech_type,
                flags,
                locally_initiated,
                established
            )
            src_name = Name(src_name)
            target_name = Name(target_name)
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])

            mech = OID(mech_type[0][0]) if mech_type[0] else None

            if locally_initiated:
                new_context_obj = InitContext(target_name, mech_type=mech)
            else:
                new_context_obj = AcceptContext()
                new_context_obj.peer_name = src_name
            new_context_obj.mech_type = mech
            new_context_obj.flags = flags[0]
            new_context_obj.established = bool(established[0])
            new_context_obj._ctx = ffi.gc(new_context, _release_gss_ctx_id_t)
            return new_context_obj
        except:
            if new_context[0]:
                C.gss_delete_sec_context(
                    minor_status,
                    new_context,
                    ffi.cast('gss_buffer_t', C.GSS_C_NO_BUFFER)
                )
            raise

    @property
    def lifetime(self):
        """
        The lifetime of the context in seconds (only valid after :meth:`step` has been called). If
        the context does not have a time limit on its validity, this will be
        :const:`gssapi.C_INDEFINITE`
        """

        minor_status = ffi.new('OM_uint32[1]')
        lifetime_rec = ffi.new('OM_uint32[1]')

        retval = C.gss_inquire_context(
            minor_status,
            self._ctx[0],
            ffi.NULL,  # src_name
            ffi.NULL,  # target_name
            lifetime_rec,
            ffi.NULL,  # mech_type
            ffi.NULL,  # ctx_flags
            ffi.NULL,  # locally_initiated
            ffi.NULL   # established
        )
        if GSS_ERROR(retval):
            if minor_status[0] and self.mech_type:
                raise _exception_for_status(retval, minor_status[0], self.mech_type)
            else:
                raise _exception_for_status(retval, minor_status[0])
        return lifetime_rec[0]

    def delete(self):
        """
        Delete a security context. This method will delete the local data structures associated
        with the specified security context, and may return an output token, which when passed to
        :meth:`process_context_token` on the peer may instruct it to also delete its context.

        RFC 2744 recommends that GSSAPI mechanisms do not emit any output token when they're
        deleted, so this behaviour could be considered deprecated.

        After this method is called, this security context will become invalid and should not be
        used in any way.

        :returns: An output token if one was emitted by the GSSAPI mechanism, otherwise an empty
            bytestring.
        :rtype: bytes
        """

        if not self._ctx[0]:
            raise GSSException("Can't delete invalid context")
        output_token_buffer = ffi.new('gss_buffer_desc[1]')
        minor_status = ffi.new('OM_uint32[1]')
        retval = C.gss_delete_sec_context(
            minor_status,
            self._ctx,
            output_token_buffer
        )
        self._ctx = ffi.new('gss_ctx_id_t[1]')
        self._reset_flags()
        try:
            if GSS_ERROR(retval):
                if minor_status[0] and self.mech_type:
                    raise _exception_for_status(retval, minor_status[0], self.mech_type)
                else:
                    raise _exception_for_status(retval, minor_status[0])

            return _buf_to_str(output_token_buffer[0])
        finally:
            if output_token_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_token_buffer)


class InitContext(Context):
    """
    An instance of this class can be used to initiate a secure context between two applications.
    The application using :class:`InitContext` must specify the :class:`~gssapi.names.Name` of the
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
    :param input_chan_bindings: Optional channel bindings object, to bind this security context to
        an underlying communications channel.
    :type input_chan_bindings: :class:`~gssapi.chanbind.ChannelBindings`
    """

    def __init__(self, peer_name, cred=C.GSS_C_NO_CREDENTIAL, mech_type=None, req_flags=(), time_req=0,
                 input_chan_bindings=C.GSS_C_NO_CHANNEL_BINDINGS):
        super(InitContext, self).__init__()
        self.peer_name = peer_name

        if hasattr(cred, '_cred'):
            self._cred_object = cred
        elif cred == C.GSS_C_NO_CREDENTIAL:
            self._cred_object = None
        else:
            raise TypeError(
                "Expected a gssapi.Credential object or gssapi.C_NO_CREDENTIAL, got {0}".format(
                    type(cred)
                )
            )

        self._desired_mech = mech_type
        self._req_flags = functools.reduce(operator.or_, req_flags, 0)
        self._time_req = time_req

        if (
            hasattr(input_chan_bindings, '_cb')
            and isinstance(input_chan_bindings._cb, ffi.CData)
            and ffi.typeof(input_chan_bindings._cb) == ffi.typeof('gss_channel_bindings_t')
        ):
            self._channel_bindings = input_chan_bindings._cb
        else:
            self._channel_bindings = ffi.cast(
                'gss_channel_bindings_t', C.GSS_C_NO_CHANNEL_BINDINGS
            )

    def step(self, input_token=None):
        """Performs a step to establish the context as an initiator.

        This method should be called in a loop and fed input tokens from the acceptor, and its
        output tokens should be sent to the acceptor, until this context's :attr:`established`
        attribute is True.

        :param input_token: The input token from the acceptor (omit this param or pass None on
            the first call).
        :type input_token: bytes
        :returns: either a byte string with the next token to send to the acceptor,
            or None if there is no further token to send to the acceptor.
        :raises: :exc:`~gssapi.error.GSSException` if there is an error establishing the context.
        """

        minor_status = ffi.new('OM_uint32[1]')

        if input_token:
            input_token_buffer = ffi.new('gss_buffer_desc[1]')
            input_token_buffer[0].length = len(input_token)
            c_str_input_token = ffi.new('char[]', input_token)
            input_token_buffer[0].value = c_str_input_token
        else:
            input_token_buffer = ffi.cast('gss_buffer_t', C.GSS_C_NO_BUFFER)

        if isinstance(self._desired_mech, OID):
            desired_mech = ffi.addressof(self._desired_mech._oid)
        else:
            desired_mech = ffi.cast('gss_OID', C.GSS_C_NO_OID)

        actual_mech = ffi.new('gss_OID[1]')
        output_token_buffer = ffi.new('gss_buffer_desc[1]')
        actual_flags = ffi.new('OM_uint32[1]')
        actual_time = ffi.new('OM_uint32[1]')

        if self._cred_object is not None:
            cred = self._cred_object._cred[0]
        else:
            cred = ffi.cast('gss_cred_id_t', C.GSS_C_NO_CREDENTIAL)

        retval = C.gss_init_sec_context(
            minor_status,
            cred,
            self._ctx,
            self.peer_name._name[0],
            desired_mech,
            self._req_flags,
            self._time_req,
            self._channel_bindings,
            input_token_buffer,
            actual_mech,
            output_token_buffer,
            actual_flags,
            actual_time
        )
        try:
            if output_token_buffer[0].length != 0:
                out_token = _buf_to_str(output_token_buffer[0])
            else:
                out_token = None

            if GSS_ERROR(retval):
                if minor_status[0] and actual_mech[0]:
                    raise _exception_for_status(retval, minor_status[0], actual_mech[0], out_token)
                else:
                    raise _exception_for_status(retval, minor_status[0], None, out_token)

            self.established = not (retval & C.GSS_S_CONTINUE_NEEDED)
            self.flags = actual_flags[0]

            if actual_mech[0]:
                self.mech_type = OID(actual_mech[0][0])

            return out_token
        except:
            if self._ctx[0]:
                C.gss_delete_sec_context(
                    minor_status,
                    self._ctx,
                    ffi.cast('gss_buffer_t', C.GSS_C_NO_BUFFER)
                )
                self._reset_flags()
            raise
        finally:
            if output_token_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_token_buffer)


class AcceptContext(Context):
    """
    This class is used to accept a connection from an initiator and establish and manage a security
    context on the acceptor side. The initiator is normally authenticated as part of the context
    establishment process, though some mechanisms support anonymous peers.

    :param cred: The credential to use for the acceptor. Omit this parameter to use the default
        acceptor credentials (e.g. any principal in the default keytab, when the Kerberos mechanism
        is used).
    :type cred: :class:`~gssapi.creds.Credential`
    :param input_chan_bindings: Optional channel bindings object, to bind this security context to
        an underlying communications channel.
    :type input_chan_bindings: :class:`~gssapi.chanbind.ChannelBindings`

    .. py:attribute:: delegated_cred

        If the initiator delegated a credential to this acceptor, this will be
        :class:`~gssapi.creds.Credential` object containing the delegated credential. Otherwise
        it will be set to None.

    .. py:attribute:: peer_name

        If this context has authenticated an initiator, this will be a
        :class:`~gssapi.names.MechName` object representing the initiator. Otherwise it will be set
        to None.
    """

    def __init__(self, cred=C.GSS_C_NO_CREDENTIAL, input_chan_bindings=C.GSS_C_NO_CHANNEL_BINDINGS):
        super(AcceptContext, self).__init__()

        if hasattr(cred, '_cred'):
            self._cred_object = cred
        elif cred == C.GSS_C_NO_CREDENTIAL:
            self._cred_object = None
        else:
            raise TypeError(
                "Expected a gssapi.Credential object or gssapi.C_NO_CREDENTIAL, got {0}".format(
                    type(cred)
                )
            )
        self.delegated_cred = None
        self.peer_name = None

        if (
            hasattr(input_chan_bindings, '_cb')
            and isinstance(input_chan_bindings._cb, ffi.CData)
            and ffi.typeof(input_chan_bindings._cb) == ffi.typeof('gss_channel_bindings_t')
        ):
            self._channel_bindings = input_chan_bindings._cb
        else:
            self._channel_bindings = ffi.cast('gss_channel_bindings_t', C.GSS_C_NO_CHANNEL_BINDINGS)

    def step(self, input_token):
        """Performs a step to establish the context as an acceptor.

        This method should be called in a loop and fed input tokens from the initiator, and its
        output tokens should be sent to the initiator, until this context's :attr:`established`
        attribute is True.

        :param input_token: The input token from the initiator (required).
        :type input_token: bytes
        :returns: either a byte string with the next token to send to the initiator,
            or None if there is no further token to send to the initiator.
        :raises: :exc:`~gssapi.error.GSSException` if there is an error establishing the context.
        """
        minor_status = ffi.new('OM_uint32[1]')
        input_token_buffer = ffi.new('gss_buffer_desc[1]')
        input_token_buffer[0].length = len(input_token)
        c_str_import_token = ffi.new('char[]', input_token)
        input_token_buffer[0].value = c_str_import_token

        mech_type = ffi.new('gss_OID[1]')
        output_token_buffer = ffi.new('gss_buffer_desc[1]')
        src_name_handle = ffi.new('gss_name_t[1]')
        actual_flags = ffi.new('OM_uint32[1]')
        time_rec = ffi.new('OM_uint32[1]')
        delegated_cred_handle = ffi.new('gss_cred_id_t[1]')

        if self._cred_object is not None:
            cred = self._cred_object._cred[0]
        else:
            cred = ffi.cast('gss_cred_id_t', C.GSS_C_NO_CREDENTIAL)

        retval = C.gss_accept_sec_context(
            minor_status,
            self._ctx,
            cred,
            input_token_buffer,
            self._channel_bindings,
            src_name_handle,
            mech_type,
            output_token_buffer,
            actual_flags,
            time_rec,
            delegated_cred_handle
        )
        if src_name_handle[0]:
            src_name = MechName(src_name_handle, mech_type[0])  # make sure src_name is GC'd
        try:
            if output_token_buffer[0].length != 0:
                out_token = _buf_to_str(output_token_buffer[0])
            else:
                out_token = None

            if GSS_ERROR(retval):
                if minor_status[0] and mech_type[0]:
                    raise _exception_for_status(retval, minor_status[0], mech_type[0], out_token)
                else:
                    raise _exception_for_status(retval, minor_status[0], None, out_token)

            self.established = not (retval & C.GSS_S_CONTINUE_NEEDED)
            self.flags = actual_flags[0]

            if (self.flags & C.GSS_C_DELEG_FLAG):
                self.delegated_cred = Credential(delegated_cred_handle)

            if mech_type[0]:
                self.mech_type = OID(mech_type[0][0])

                if src_name_handle[0]:
                    src_name._mech_type = self.mech_type
                    self.peer_name = src_name

            return out_token
        except:
            if self._ctx:
                C.gss_delete_sec_context(
                    minor_status,
                    self._ctx,
                    ffi.cast('gss_buffer_t', C.GSS_C_NO_BUFFER)
                )
                self._reset_flags()
            raise
        finally:
            if output_token_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_token_buffer)
            # if self.delegated_cred is present, it will handle gss_release_cred:
            if delegated_cred_handle[0] and not self.delegated_cred:
                C.gss_release_cred(minor_status, delegated_cred_handle)
