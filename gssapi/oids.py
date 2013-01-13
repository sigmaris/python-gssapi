from __future__ import absolute_import

from ctypes import pointer, byref, c_int, string_at

from pyasn1.codec.ber import decoder

from .gssapi_h import (
    GSS_C_NO_OID_SET, GSS_S_COMPLETE,
    OM_uint32, gss_OID, gss_OID_desc, gss_OID_set,
    gss_release_oid_set, gss_create_empty_oid_set, gss_test_oid_set_member,
    gss_indicate_mechs
)
from . import GSSException


def get_all_mechs():
    minor_status = OM_uint32()
    mech_set = gss_OID_set()
    gss_indicate_mechs(pointer(minor_status), pointer(mech_set))
    return OIDSet(oid_set=mech_set)


class OID(object):
    """Wraps a gss_OID"""

    _oid_names = {
        "1.2.840.113554.1.2.2":   "Kerberos v5",
        "1.3.6.1.5.5.2":          "SPNEGO",
        "1.2.752.43.14.2":        "Microsoft Netlogon SSP",
        "1.3.6.1.5.5.14":         "SCRAM-SHA-1",
        "1.3.6.1.4.1.311.2.2.10": "NTLM",
        "1.3.6.1.5.2.5":          "IAKERB"
    }

    def __init__(self, oid):
        super(OID, self).__init__()
        self._oid = oid

    def __repr__(self):
        tag = b'\x06'
        length = chr(self._oid.length)
        value = string_at(self._oid.elements, self._oid.length)
        return "OID({0})".format(decoder.decode(tag + length + value)[0])

    def __str__(self):
        tag = b'\x06'
        length = chr(self._oid.length)
        value = string_at(self._oid.elements, self._oid.length)
        oid_str = str(decoder.decode(tag + length + value)[0])
        if oid_str in self._oid_names:
            return "{0} ({1})".format(oid_str, self._oid_names[oid_str])
        else:
            return oid_str


class OIDSet(object):
    """Wraps a gss_OID_set"""
    def __init__(self, oid_set=None):
        super(OIDSet, self).__init__()

        if not oid_set:
            minor_status = OM_uint32()
            self._oid_set = gss_OID_set()
            retval = gss_create_empty_oid_set(byref(minor_status), byref(self._oid_set))
            if retval != GSS_S_COMPLETE:
                self.release()
                raise GSSException(retval, minor_status)
        elif isinstance(oid_set, gss_OID_set):
            self._oid_set = oid_set
        else:
            raise TypeError("Expected a gss_OID_set, got " + str(type(oid_set)))

    def __contains__(self, other_oid):
        if not self._oid_set or not isinstance(other_oid, OID):
            return False

        minor_status = OM_uint32()
        present = c_int()
        gss_test_oid_set_member(
            byref(minor_status), byref(other_oid._oid), self._oid_set, byref(present)
        )
        return bool(present)

    def __len__(self):
        if not self._oid_set:
            return 0
        else:
            return self._oid_set.contents.count

    def __getitem__(self, index):
        if not self._oid_set or index < 0 or index >= self._oid_set.contents.count:
            raise IndexError("Index out of range.")

        return OID(self._oid_set.contents.elements[index])

    def release(self):
        """Releases storage backing this OIDSet. After calling this method,
        this OIDSet can no longer be used. It shouldn't be necessary as the
        storage will be released when the object is GCd, anyway."""
        if self._oid_set:
            minor_status = OM_uint32()
            gss_release_oid_set(byref(minor_status), byref(self._oid_set))
            self._oid_set = GSS_C_NO_OID_SET

    def __del__(self):
        self.release()
