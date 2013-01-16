from __future__ import absolute_import

from ctypes import byref, string_at, cast

from .gssapi_h import (
    GSS_C_GSS_CODE, GSS_C_MECH_CODE, GSS_C_NO_OID,
    GSS_S_COMPLETE, GSS_S_BAD_MECH, GSS_S_BAD_STATUS,
    OM_uint32, gss_buffer_desc, gss_OID,
    gss_display_status, gss_release_buffer
)


def buf_to_str(buf):
    """Converts a gss_buffer_desc containing a char * string to a Python str"""
    return string_at(buf.value, buf.length)


def status_list(maj_status, min_status, status_type=GSS_C_GSS_CODE, mech_type=GSS_C_NO_OID):
    """Creates a "friendly" error message from a GSS status code."""
    from .oids import OID

    statuses = []
    message_context = OM_uint32(0)
    minor_status = OM_uint32()

    if isinstance(mech_type, OID):
        mech_type = OID._oid
    else:
        mech_type = cast(mech_type, gss_OID)

    while True:
        status_buf = gss_buffer_desc()

        try:
            retval = gss_display_status(
                byref(minor_status),
                maj_status,
                status_type,
                mech_type,
                byref(message_context),
                byref(status_buf)
            )
            if retval == GSS_S_COMPLETE:
                statuses.append(string_at(status_buf.value, status_buf.length))
            elif retval == GSS_S_BAD_MECH:
                statuses.append("Unsupported mechanism type passed to GSSException")
            elif retval == GSS_S_BAD_STATUS:
                statuses.append("Unrecognized status value passed to GSSException")
        finally:
            gss_release_buffer(byref(minor_status), byref(status_buf))

        if message_context.value == 0:
            break

    if min_status:
        statuses.append(b"Minor code:")
        statuses.extend(status_list(min_status, 0, GSS_C_MECH_CODE, mech_type))
    return statuses


def status_to_str(maj_status, min_status, mech_type=GSS_C_NO_OID):
    return b'\n'.join(status_list(maj_status, min_status, mech_type=mech_type))


class GSSException(Exception):
    """Represents a GSSAPI error"""

    def __init__(self, maj_status, min_status):
        super(GSSException, self).__init__()
        self.maj_status = maj_status
        self.min_status = min_status
        self.message = status_to_str(maj_status, min_status)

    def __str__(self):
        return self.message


class GSSMechException(Exception):
    """Represents a GSSAPI mechanism-specific error"""

    def __init__(self, maj_status, min_status, mech_type):
        super(GSSMechException, self).__init__()
        self.maj_status = maj_status
        self.min_status = min_status
        self.message = status_to_str(maj_status, min_status, mech_type)

    def __str__(self):
        return self.message
