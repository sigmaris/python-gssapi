from __future__ import absolute_import

from ctypes import pointer, string_at

from . import gssapi_h

from .gssapi_h import (
    GSS_C_GSS_CODE, GSS_C_MECH_CODE, GSS_C_NO_OID,
    GSS_S_COMPLETE,
    OM_uint32, gss_buffer_desc,
    gss_display_status, gss_release_buffer
)

gssapi_h.struct_gss_name_struct._pack_ = 2
gssapi_h.struct_gss_cred_id_struct._pack_ = 2
gssapi_h.struct_gss_ctx_id_struct._pack_ = 2
gssapi_h.struct_gss_OID_desc_struct._pack_ = 2
gssapi_h.struct_gss_OID_set_desc_struct._pack_ = 2
gssapi_h.struct_gss_buffer_desc_struct._pack_ = 2
gssapi_h.struct_gss_channel_bindings_struct._pack_ = 2


def buf_to_str(buf):
    """Converts a gss_buffer_desc containing a char * string to a Python str"""
    return string_at(buf.value, buf.length)


def status_list(maj_status, min_status, status_type=GSS_C_GSS_CODE, mech_type=GSS_C_NO_OID):
    """Creates a "friendly" error message from a GSS status code."""

    statuses = []
    maj_status_c = OM_uint32(maj_status)
    message_context = OM_uint32(0)
    minor_status = OM_uint32()
    while True:
        status_buf = gss_buffer_desc()

        try:
            retval = gss_display_status(
                pointer(minor_status),
                maj_status_c,
                status_type,
                mech_type,
                pointer(message_context),
                pointer(status_buf)
            )
            if retval != GSS_S_COMPLETE:
                raise GSSException(retval, minor_status)

            statuses.append(string_at(status_buf.value, status_buf.length))
        finally:
            gss_release_buffer(pointer(minor_status), pointer(status_buf))

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
