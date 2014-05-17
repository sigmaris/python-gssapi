"""
All GSSAPI-related exceptions raised by this library are subclasses of
:class:`~gssapi.error.GSSException`. Errors reported by the C API are represented by subclasses of
:class:`~gssapi.error.GSSCException`, and errors which are reported by the C API and are specific
to a given mechanism are represented by subclasses of :class:`~gssapi.error.GSSMechException`.
There are then specific exception classes for each of the error statuses defined in
`RFC 2744 Section 3.9.1 <http://tools.ietf.org/html/rfc2744#section-3.9.1>`_, for example
:class:`~gssapi.error.BadStructure` or :class:`~gssapi.error.CredentialsExpired`.

Note that exceptions raised by the library may inherit from more than one exception class, for
example an exception raised by :meth:`~gssapi.ctx.Context.verify_mic` may be an instance of both
:class:`~gssapi.error.BadSignature` and also :class:`~gssapi.error.GSSMechException`.
"""
from __future__ import absolute_import

from .bindings import ffi, C, _buf_to_str, GSS_CALLING_ERROR, GSS_ROUTINE_ERROR


def status_list(maj_status, min_status, status_type=C.GSS_C_GSS_CODE, mech_type=C.GSS_C_NO_OID):
    """
    Creates a "friendly" error message from a GSS status code. This is used to create the
    :attr:`GSSCException.message` of a :class:`GSSCException`.

    :param maj_status: The major status reported by the C GSSAPI.
    :type maj_status: int
    :param min_status: The minor status reported by the C GSSAPI.
    :type min_status: int
    :param status_type: Whether the status is a general GSSAPI status or a mechanism status.
    :type status_type: ``GSS_C_GSS_CODE`` or ``GSS_C_MECH_CODE``
    :param mech_type: Optional mechanism type, if the status is a mechanism status.
    :type mech_type: :class:`~gssapi.oids.OID`
    :returns: a list of strings describing the error.
    :rtype: list of strings
    """
    from .oids import OID

    statuses = []
    message_context = ffi.new('OM_uint32[1]')
    minor_status = ffi.new('OM_uint32[1]')

    if isinstance(mech_type, OID):
        mech_type = ffi.addressof(mech_type._oid)  # OID._oid is type "struct gss_OID_desc"
    elif mech_type == C.GSS_C_NO_OID:
        mech_type = ffi.cast('gss_OID', C.GSS_C_NO_OID)
    elif not isinstance(mech_type, ffi.CData) or ffi.typeof(mech_type) != ffi.typeof('gss_OID'):
        raise TypeError(
            "Expected mech_type to be a gssapi.oids.OID or gss_OID, got {0}".format(type(mech_type))
        )

    while True:
        status_buf = ffi.new('gss_buffer_desc[1]')

        try:
            retval = C.gss_display_status(
                minor_status,
                maj_status,
                status_type,
                mech_type,
                message_context,
                status_buf
            )
            if retval == C.GSS_S_COMPLETE:
                statuses.append("({0}) {1}.".format(
                    maj_status,
                    _buf_to_str(status_buf[0]).decode("utf-8", errors="replace")
                ))
            elif retval == C.GSS_S_BAD_MECH:
                statuses.append("Unsupported mechanism type passed to GSSException")
                break
            elif retval == C.GSS_S_BAD_STATUS:
                statuses.append("Unrecognized status value passed to GSSException")
                break
        finally:
            C.gss_release_buffer(minor_status, status_buf)

        if message_context[0] == 0:
            break

    if min_status:
        minor_status_msgs = status_list(min_status, 0, C.GSS_C_MECH_CODE, mech_type)
        if minor_status_msgs:
            statuses.append("Minor code:")
            statuses.extend(minor_status_msgs)
    return statuses


def _status_to_str(maj_status, min_status, mech_type=C.GSS_C_NO_OID):
    return ' '.join(status_list(maj_status, min_status, mech_type=mech_type))


class GSSException(Exception):
    """
    Represents a GSSAPI Exception.

    .. py:attribute:: token

        If the exception was raised as a result of a failure to establish a security context, this
        attribute may be set to a bytestring which should be sent to the peer of the security
        context, to notify the peer that context establishment failed and that they should delete
        their associated security context.
        If not applicable, the attribute will be set to None.
    """
    def __init__(self, *args, **kwargs):
        super(GSSException, self).__init__(*args)
        self.token = kwargs.get('token')


class GSSCException(GSSException):
    """
    Represents a GSSAPI error reported by the C GSSAPI.

    .. py:attribute:: maj_status

        The major status code reported by the C GSSAPI which caused this exception.

    .. py:attribute:: min_status

        The minor status code (normally mechanism-specific) reported by the C GSSAPI which caused
        this exception.

    .. py:attribute:: message

        A string describing the error created by the C GSSAPI.
    """

    def __init__(self, maj_status, min_status, token=None):
        super(GSSCException, self).__init__(token=token)
        self.maj_status = maj_status
        self.min_status = min_status
        self._create_message()

    def _create_message(self):
        self.message = _status_to_str(self.maj_status, self.min_status)

    def __str__(self):
        return self.message


class GSSMechException(GSSCException):
    """
    Represents a GSSAPI mechanism-specific error reported by the C GSSAPI.

    .. py:attribute:: maj_status

        The major status code reported by the C GSSAPI which caused this exception.

    .. py:attribute:: min_status

        The minor status code (normally mechanism-specific) reported by the C GSSAPI which caused
        this exception.

    .. py:attribute:: message

        A string describing the error created by the C GSSAPI.

    .. py:attribute:: mech_type

        An :class:`~gssapi.oids.OID` representing the mechanism which caused this exception.
    """

    def __init__(self, maj_status, min_status, mech_type, token=None):
        self.mech_type = mech_type
        super(GSSMechException, self).__init__(maj_status, min_status, token)

    def _create_message(self):
        self.message = _status_to_str(self.maj_status, self.min_status, self.mech_type)


# Parent classes for types of error:
class GSSCallingError(GSSCException):
    """
    Parent class for errors that are specific to the C language bindings.
    """


class GSSRoutineError(GSSCException):
    """
    Parent class for errors that are defined in the GSS-API specification.
    """


# non-mech-specific Calling errors:
class InaccessibleRead(GSSCallingError):
    """
    A required input parameter could not be read.
    Corresponds to a status of :attr:`~gssapi.S_CALL_INACCESSIBLE_READ`.
    """


class InaccessibleWrite(GSSCallingError):
    """
    A required output parameter could not be written.
    Corresponds to a status of :attr:`~gssapi.S_CALL_INACCESSIBLE_WRITE`.
    """


class BadStructure(GSSCallingError):
    """
    A parameter was malformed.
    Corresponds to a status of :attr:`~gssapi.S_CALL_BAD_STRUCTURE`.
    """


# non-mech-specific Routine errors
class BadMechanism(GSSRoutineError):
    """
    An unsupported mechanism was requested.
    Corresponds to a status of :attr:`~gssapi.S_BAD_MECH`.
    """


class BadName(GSSRoutineError):
    """
    An invalid name was supplied.
    Corresponds to a status of :attr:`~gssapi.S_BAD_NAME`.
    """


class BadNameType(GSSRoutineError):
    """
    A supplied name was of an unsupported type.
    Corresponds to a status of :attr:`~gssapi.S_BAD_NAMETYPE`.
    """


class BadBindings(GSSRoutineError):
    """
    Incorrect channel bindings were supplied.
    Corresponds to a status of :attr:`~gssapi.S_BAD_BINDINGS`.
    """


class BadStatus(GSSRoutineError):
    """
    An invalid status code was supplied.
    Corresponds to a status of :attr:`~gssapi.S_BAD_STATUS`.
    """


class BadSignature(GSSRoutineError):
    """
    A token had an invalid MIC.
    Corresponds to a status of :attr:`~gssapi.S_BAD_SIG`.
    """


class NoCredential(GSSRoutineError):
    """
    No credentials were supplied, or the credentials were unavailable or inaccessible.
    Corresponds to a status of :attr:`~gssapi.S_NO_CRED`.
    """


class NoContext(GSSRoutineError):
    """
    No context has been established.
    Corresponds to a status of :attr:`~gssapi.S_NO_CONTEXT`.
    """


class DefectiveToken(GSSRoutineError):
    """
    A token was invalid.
    Corresponds to a status of :attr:`~gssapi.S_DEFECTIVE_TOKEN`.
    """


class DefectiveCredential(GSSRoutineError):
    """
    A credential was invalid.
    Corresponds to a status of :attr:`~gssapi.S_DEFECTIVE_CREDENTIAL`.
    """


class CredentialsExpired(GSSRoutineError):
    """
    The referenced credentials have expired.
    Corresponds to a status of :attr:`~gssapi.S_CREDENTIALS_EXPIRED`.
    """


class ContextExpired(GSSRoutineError):
    """
    The context has expired.
    Corresponds to a status of :attr:`~gssapi.S_CONTEXT_EXPIRED`.
    """


class Failure(GSSRoutineError):
    """
    Miscellaneous failure.
    Corresponds to a status of :attr:`~gssapi.S_FAILURE`.
    """


class BadQOP(GSSRoutineError):
    """
    The quality-of-protection requested could not be provided.
    Corresponds to a status of :attr:`~gssapi.S_BAD_QOP`.
    """


class Unauthorized(GSSRoutineError):
    """
    The operation is forbidden by local security policy.
    Corresponds to a status of :attr:`~gssapi.S_UNAUTHORIZED`.
    """


class Unavailable(GSSRoutineError):
    """
    The operation or option is unavailable.
    Corresponds to a status of :attr:`~gssapi.S_UNAVAILABLE`.
    """


class DuplicateElement(GSSRoutineError):
    """
    The requested credential element already exists.
    Corresponds to a status of :attr:`~gssapi.S_DUPLICATE_ELEMENT`.
    """


class NameNotMechName(GSSRoutineError):
    """
    The provided name was not a mechanism name.
    Corresponds to a status of :attr:`~gssapi.S_NAME_NOT_MN`.
    """


def _exception_for_status(maj_status, min_status, mech_type=None, token=None):
    if mech_type is not None:
        exc_types = [GSSMechException]
        exc_name = 'Mech'
        exc_args = (maj_status, min_status, mech_type, token)
    else:
        exc_types = []
        exc_name = ''
        exc_args = (maj_status, min_status, token)

    if GSS_CALLING_ERROR(maj_status):
        for exc_class, status in (
            (InaccessibleRead, C.GSS_S_CALL_INACCESSIBLE_READ),
            (InaccessibleWrite, C.GSS_S_CALL_INACCESSIBLE_WRITE),
            (BadStructure, C.GSS_S_CALL_BAD_STRUCTURE),
        ):
            if GSS_CALLING_ERROR(maj_status) == status:
                exc_types.append(exc_class)
                exc_name += exc_class.__name__
                break
    if GSS_ROUTINE_ERROR(maj_status):
        for exc_class, status in (
            (BadMechanism, C.GSS_S_BAD_MECH),
            (BadName, C.GSS_S_BAD_NAME),
            (BadNameType, C.GSS_S_BAD_NAMETYPE),
            (BadBindings, C.GSS_S_BAD_BINDINGS),
            (BadStatus, C.GSS_S_BAD_STATUS),
            (BadSignature, C.GSS_S_BAD_SIG),
            (NoCredential, C.GSS_S_NO_CRED),
            (NoContext, C.GSS_S_NO_CONTEXT),
            (DefectiveToken, C.GSS_S_DEFECTIVE_TOKEN),
            (DefectiveCredential, C.GSS_S_DEFECTIVE_CREDENTIAL),
            (CredentialsExpired, C.GSS_S_CREDENTIALS_EXPIRED),
            (ContextExpired, C.GSS_S_CONTEXT_EXPIRED),
            (Failure, C.GSS_S_FAILURE),
            (BadQOP, C.GSS_S_BAD_QOP),
            (Unauthorized, C.GSS_S_UNAUTHORIZED),
            (Unavailable, C.GSS_S_UNAVAILABLE),
            (DuplicateElement, C.GSS_S_DUPLICATE_ELEMENT),
            (NameNotMechName, C.GSS_S_NAME_NOT_MN),
        ):
            if GSS_ROUTINE_ERROR(maj_status) == status:
                exc_types.append(exc_class)
                exc_name += exc_class.__name__
                break
    if len(exc_types) == 0:
        return GSSCException(*exc_args)
    elif len(exc_types) == 1:
        # It is a simple error
        return exc_types[0](*exc_args)
    else:
        # It's an error of more than one of the above types
        return type(exc_name, tuple(exc_types), {})(*exc_args)
