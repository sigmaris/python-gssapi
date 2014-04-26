from __future__ import absolute_import

import re
import sys
import struct
from pyasn1.codec.ber import decoder

from .bindings import ffi, C, GSS_ERROR
from .error import _exception_for_status, GSSException


def _release_OID_set(oid_set):
    if oid_set[0]:
        C.gss_release_oid_set(ffi.new('OM_uint32[1]'), oid_set)


def get_all_mechs():
    """
    Return an :class:`OIDSet` of all the mechanisms supported by the underlying GSSAPI
    implementation.
    """
    minor_status = ffi.new('OM_uint32[1]')
    mech_set = ffi.new('gss_OID_set[1]')
    try:
        retval = C.gss_indicate_mechs(minor_status, mech_set)
        if GSS_ERROR(retval):
            raise _exception_for_status(retval, minor_status[0])
    except:
        _release_OID_set(mech_set)
        raise
    return OIDSet(oid_set=mech_set)


class OID(object):
    """
    Represents an `Object Identifier <http://en.wikipedia.org/wiki/Object_identifier>`_. These are
    used by GSSAPI to identify mechanism types, and name types, amongst other things.

    Normally there is no reason to construct instances of this class directly; objects of this
    class are returned from :meth:`get_all_mechs` or :meth:`mech_from_string` to identify
    mechanisms, as the :attr:`~gssapi.ctx.Context.mech_type` attribute of
    :class:`~gssapi.ctx.Context` objects, and as the :attr:`~gssapi.names.Name.type` attribute of
    :class:`~gssapi.names.Name` objects.
    """

    def __init__(self, oid, parent_set=None):
        super(OID, self).__init__()
        self._oid = oid
        self._parent = parent_set

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        if isinstance(other, OID):
            return str(other) == str(self)
        else:
            return False

    def __hash__(self):
        hsh = 31
        for c in ffi.buffer(self._oid.elements, self._oid.length):
            if sys.version_info >= (3,):
                hsh = 101 * hsh + c[0]
            else:
                hsh = 101 * hsh + ord(c)
        return hsh

    @staticmethod
    def mech_from_string(input_string):
        """
        Takes a string form of a mechanism OID, in dot-separated: "1.2.840.113554.1.2.2" or numeric
        ASN.1: "{1 2 840 113554 1 2 2}" notation, and returns an :class:`OID` object representing
        the mechanism, which can be passed to other GSSAPI methods.

        :param input_string: a string representing the desired mechanism OID.
        :returns: the mechanism OID.
        :rtype: :class:`OID`
        :raises: ValueError if the the input string is ill-formatted.
        :raises: KeyError if the mechanism identified by the string is not supported by the
            underlying GSSAPI implementation.
        """
        if not re.match(r'^\d+(\.\d+)*$', input_string):
            if re.match(r'^\{\d+( \d+)*\}$', input_string):
                input_string = ".".join(input_string[1:-1].split())
            else:
                raise ValueError(input_string)
        for mech in get_all_mechs():
            if input_string == str(mech):
                return mech
        raise KeyError("Unknown mechanism: {0}".format(input_string))

    def __repr__(self):
        return "OID({0})".format(self)

    def __str__(self):
        tag = b'\x06'
        length = struct.pack('B', self._oid.length)
        value = ffi.buffer(self._oid.elements, self._oid.length)[:]
        return str(decoder.decode(tag + length + value)[0])


class OIDSet(object):
    """
    Represents a set of OIDs returned by the GSSAPI. This object supports array access to the OIDs
    contained within. This set is immutable; if you need to incrementally create an :class:`OIDSet`
    by adding :class:`OID` objects to it, use :class:`MutableOIDSet`.
    """

    def __init__(self, oid_set=None):
        """Wraps a gss_OID_set. This can be returned from methods like gss_inquire_cred
        where it shouldn't be modified by the caller, since it's immutable."""
        super(OIDSet, self).__init__()

        if isinstance(oid_set, ffi.CData) and ffi.typeof(oid_set) == ffi.typeof('gss_OID_set[1]'):
            self._oid_set = ffi.gc(oid_set, _release_OID_set)
        elif oid_set is None:
            self._oid_set = ffi.new('gss_OID_set[1]')
            minor_status = ffi.new('OM_uint32[1]')
            try:
                retval = C.gss_create_empty_oid_set(minor_status, self._oid_set)
                if GSS_ERROR(retval):
                    raise _exception_for_status(retval, minor_status[0])
                self._oid_set = ffi.gc(self._oid_set, _release_OID_set)
            except:
                _release_OID_set(self._oid_set)
                raise
        else:
            raise TypeError("Expected a gss_OID_set *, got " + str(type(oid_set)))

    def __contains__(self, other_oid):
        if not self._oid_set[0]:
            return False
        if not (
            isinstance(other_oid, OID)
            or (
                isinstance(other_oid, ffi.CData)
                and ffi.typeof(other_oid) == ffi.typeof('gss_OID_desc')
            )
        ):
            return False

        minor_status = ffi.new('OM_uint32[1]')
        present = ffi.new('int[1]')
        C.gss_test_oid_set_member(
            minor_status, ffi.addressof(other_oid._oid), self._oid_set[0], present
        )
        return bool(present[0])

    def __len__(self):
        if not self._oid_set[0]:
            return 0
        else:
            return self._oid_set[0].count

    def __getitem__(self, index):
        if index < 0:
            index = len(self) + index
        if not self._oid_set[0] or index < 0 or index >= self._oid_set[0].count:
            raise IndexError("Index out of range.")

        return OID(self._oid_set[0].elements[index], self)

    @classmethod
    def singleton_set(cls, single_oid):
        """
        Factory function to create a new :class:`OIDSet` with a single member.

        :param single_oid: the OID to use as a member of the new set
        :type single_oid: :class:`OID`
        :returns: an OID set with the OID passed in as the only member
        :rtype: :class:`OIDSet`
        """
        new_set = cls()
        oid_ptr = None
        if isinstance(single_oid, OID):
            oid_ptr = ffi.addressof(single_oid._oid)
        elif isinstance(single_oid, ffi.CData):
            if ffi.typeof(single_oid) == ffi.typeof('gss_OID_desc'):
                oid_ptr = ffi.addressof(single_oid)
            elif ffi.typeof(single_oid) == ffi.typeof('gss_OID'):
                oid_ptr = single_oid
        if oid_ptr is None:
            raise TypeError("Expected a gssapi.oids.OID, got " + str(type(single_oid)))

        minor_status = ffi.new('OM_uint32[1]')
        retval = C.gss_add_oid_set_member(minor_status, oid_ptr, new_set._oid_set)
        if GSS_ERROR(retval):
            raise _exception_for_status(retval, minor_status[0])
        return new_set

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        try:
            if len(self) != len(other):
                return False
            else:
                for item in other:
                    if item not in self:
                        return False
                return True
        except TypeError:
            return False


class MutableOIDSet(OIDSet):
    """
    Represents a set of OIDs returned by the GSSAPI. This object supports array access to the OIDs
    contained within, and can also be modified by :meth:`add` to incrementally construct a set from
    a number of OIDs.

    .. py:classmethod:: singleton_set(single_oid)

        Factory function to create a new :class:`MutableOIDSet` with a single member.

        :param single_oid: the OID to use as a member of the new set
        :type single_oid: :class:`OID`
        :returns: a mutable OID set with the OID passed in as the only member
        :rtype: :class:`MutableOIDSet`
    """

    def add(self, new_oid):
        """
        Adds another :class:`OID` to this set.

        :param new_oid: the OID to add.
        :type new_oid: :class:`OID`
        """
        if self._oid_set[0]:
            oid_ptr = None
            if isinstance(new_oid, OID):
                oid_ptr = ffi.addressof(new_oid._oid)
            elif isinstance(new_oid, ffi.CData):
                if ffi.typeof(new_oid) == ffi.typeof('gss_OID_desc'):
                    oid_ptr = ffi.addressof(new_oid)
                elif ffi.typeof(new_oid) == ffi.typeof('gss_OID'):
                    oid_ptr = new_oid
            if oid_ptr is None:
                raise TypeError("Expected a gssapi.oids.OID, got " + str(type(new_oid)))

            minor_status = ffi.new('OM_uint32[1]')
            retval = C.gss_add_oid_set_member(minor_status, oid_ptr, self._oid_set)
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])
        else:
            raise GSSException("Cannot add a member to this OIDSet, its gss_OID_set is NULL!")
