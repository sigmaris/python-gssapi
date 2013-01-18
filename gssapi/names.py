from __future__ import absolute_import

from ctypes import byref, cast, c_char_p, c_void_p

from .gssapi_h import (
    GSS_C_NO_OID, GSS_C_NO_NAME, GSS_S_COMPLETE,
    OM_uint32, gss_buffer_desc, gss_name_t, gss_OID,
    gss_import_name, gss_display_name, gss_release_name, gss_release_buffer
)
from .error import GSSException, buf_to_str
from .oids import OID


class Name(object):
    """Represents an internal GSSAPI name (wraps a gss_name_t)"""

    def __init__(self, name, name_type=GSS_C_NO_OID):
        super(Name, self).__init__()

        minor_status = OM_uint32()

        name_buffer = gss_buffer_desc()
        name_buffer.length = len(name)
        name_buffer.value = cast(c_char_p(name), c_void_p)

        self._name = gss_name_t()
        if isinstance(name_type, OID):
            name_type = byref(name_type._oid)
        else:
            name_type = cast(name_type, gss_OID)

        retval = gss_import_name(
            byref(minor_status), byref(name_buffer), name_type, byref(self._name)
        )
        if retval != GSS_S_COMPLETE:
            self.release()
            raise GSSException(retval, minor_status)

    def __str__(self):
        minor_status = OM_uint32()
        out_buffer = gss_buffer_desc()

        try:
            retval = gss_display_name(
                byref(minor_status), self._name, byref(out_buffer), None
            )
            if retval != GSS_S_COMPLETE:
                raise GSSException(retval, minor_status)
            return buf_to_str(out_buffer)
        finally:
            gss_release_buffer(byref(minor_status), byref(out_buffer))

    def release(self):
        if hasattr(self, '_name') and self._name:
            minor_status = OM_uint32()
            gss_release_name(byref(minor_status), byref(self._name))
            self._name = cast(GSS_C_NO_NAME, gss_name_t)

    def canonicalize(self):
        pass

    def __del__(self):
        self.release()


class MechName(Name):
    """Represents an internal GSSAPI Mechanism Name (MN) as obtained by
    (e.g.)gss_canonicalize_name or gss_accept_sec_context."""

    def __init__(self, name, mech_type):
        """Don't construct instances of this class directly; This object will acquire
        ownership of 'name', and release the associated storage when it is deleted."""
        self._name = name
        # self._mech_type = mech_type

    # TODO: export name
