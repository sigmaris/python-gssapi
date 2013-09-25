from __future__ import absolute_import

import numbers

from ctypes import byref, cast, c_char_p, c_void_p, c_int, string_at, sizeof, pointer

from .gssapi_h import (
    GSS_C_NO_OID, GSS_C_NO_NAME, GSS_S_COMPLETE, GSS_ERROR,
    OM_uint32, gss_buffer_desc, gss_name_t, gss_OID,
    gss_import_name, gss_display_name, gss_canonicalize_name,
    gss_compare_name, gss_export_name, gss_release_name, gss_release_buffer
)
from .types_h import uid_t
from .error import GSSCException, GSSException, GSSMechException, buf_to_str


class BaseName(object):
    """Represents an internal GSSAPI name (wraps a gss_name_t)"""

    def __init__(self):
        super(BaseName, self).__init__()
        self._name = gss_name_t()

    def __str__(self):
        minor_status = OM_uint32()
        out_buffer = gss_buffer_desc()

        try:
            retval = gss_display_name(
                byref(minor_status), self._name, byref(out_buffer), None
            )
            if retval != GSS_S_COMPLETE:
                raise GSSCException(retval, minor_status)
            return buf_to_str(out_buffer)
        finally:
            gss_release_buffer(byref(minor_status), byref(out_buffer))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        if isinstance(other, BaseName):
            minor_status = OM_uint32()
            name_equal = c_int()
            retval = gss_compare_name(
                byref(minor_status),
                self._name,
                other._name,
                byref(name_equal)
            )
            if retval != GSS_S_COMPLETE:
                raise GSSCException(retval, minor_status)
            return bool(name_equal)
        else:
            return False

    def _release(self):
        if self._name:
            minor_status = OM_uint32()
            gss_release_name(byref(minor_status), byref(self._name))
            self._name = cast(GSS_C_NO_NAME, gss_name_t)

    def canonicalize(self, mech):
        if hasattr(mech, '_oid'):
            oid = mech._oid
        else:
            raise TypeError("Expected an OID, got " + str(type(mech)))

        minor_status = OM_uint32()
        out_name = gss_name_t()
        try:
            retval = gss_canonicalize_name(
                byref(minor_status), self._name, byref(oid), byref(out_name)
            )
            if retval != GSS_S_COMPLETE:
                raise GSSCException(retval, minor_status)
            return MechName(out_name, mech)
        except:
            if out_name:
                gss_release_name(byref(minor_status), byref(out_name))

    def __del__(self):
        self._release()


class Name(BaseName):

    def __init__(self, name, name_type=GSS_C_NO_OID):
        super(Name, self).__init__()

        minor_status = OM_uint32()

        name_buffer = gss_buffer_desc()
        if isinstance(name, basestring):
            name_buffer.length = len(name)
            name_buffer.value = cast(c_char_p(name), c_void_p)
        elif isinstance(name, numbers.Integral):
            c_name = uid_t(name)
            name_buffer.length = sizeof(c_name)
            name_buffer.value = cast(pointer(c_name), c_void_p)
        else:
            raise TypeError("Expected a string or int, got {0}".format(type(name)))

        if hasattr(name_type, '_oid'):
            name_type = byref(name_type._oid)
        else:
            name_type = cast(name_type, gss_OID)

        retval = gss_import_name(
            byref(minor_status), byref(name_buffer), name_type, byref(self._name)
        )
        if retval != GSS_S_COMPLETE:
            self._release()
            raise GSSCException(retval, minor_status)


class MechName(BaseName):
    """Represents an internal GSSAPI Mechanism Name (MN) as obtained by
    (e.g.)gss_canonicalize_name or gss_accept_sec_context."""

    def __init__(self, name, mech_type):
        """Don't construct instances of this class directly; This object will acquire
        ownership of 'name', and release the associated storage when it is deleted."""
        self._name = name
        self.mech_type = mech_type

    def canonicalize(self, mech):
        raise GSSException("Can't canonicalize a mechanism name.")

    def export(self):
        minor_status = OM_uint32()
        output_buffer = gss_buffer_desc()
        retval = gss_export_name(
            byref(minor_status),
            self._name,
            byref(output_buffer)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and self.mech_type:
                    raise GSSMechException(retval, minor_status, self.mech_type)
                else:
                    raise GSSCException(retval, minor_status)

            output = string_at(output_buffer.value, output_buffer.length)
            return output
        finally:
            if output_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_buffer))
