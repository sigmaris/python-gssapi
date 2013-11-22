from __future__ import absolute_import

import re
from ctypes import byref, c_int, string_at, cast

from pyasn1.codec.ber import decoder

from .headers.gssapi_h import (
    GSS_C_NO_OID_SET, GSS_S_COMPLETE,
    OM_uint32, gss_OID, gss_OID_desc, gss_OID_set,
    gss_release_oid_set, gss_create_empty_oid_set, gss_test_oid_set_member,
    gss_add_oid_set_member, gss_indicate_mechs
)
from .error import GSSCException


def get_all_mechs():
    """
    Return an :class:`OIDSet` of all the mechanisms supported by the underlying GSSAPI
    implementation.
    """
    minor_status = OM_uint32()
    mech_set = gss_OID_set()
    gss_indicate_mechs(byref(minor_status), byref(mech_set))
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
        for c in string_at(self._oid.elements, self._oid.length):
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
        length = chr(self._oid.length)
        value = string_at(self._oid.elements, self._oid.length)
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
        self._oid_set = gss_OID_set()

        if not oid_set:
            minor_status = OM_uint32()
            retval = gss_create_empty_oid_set(byref(minor_status), byref(self._oid_set))
            if retval != GSS_S_COMPLETE:
                self._release()
                raise GSSCException(retval, minor_status)
        elif isinstance(oid_set, gss_OID_set):
            self._oid_set = oid_set
        else:
            raise TypeError("Expected a gss_OID_set, got " + str(type(oid_set)))

    def __contains__(self, other_oid):
        if not self._oid_set or not hasattr(other_oid, '_oid'):
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
        if index < 0:
            index = len(self) + index
        if not self._oid_set or index < 0 or index >= self._oid_set.contents.count:
            raise IndexError("Index out of range.")

        return OID(self._oid_set.contents.elements[index], self)

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
        if isinstance(single_oid, OID):
            oid_ptr = byref(single_oid._oid)
        elif isinstance(single_oid, gss_OID_desc):
            oid_ptr = byref(single_oid)
        elif isinstance(single_oid, gss_OID):
            oid_ptr = single_oid
        else:
            raise TypeError("Expected an OID, got " + str(type(single_oid)))

        minor_status = OM_uint32()
        retval = gss_add_oid_set_member(byref(minor_status), oid_ptr, byref(new_set._oid_set))
        if retval != GSS_S_COMPLETE:
            raise GSSCException(retval, minor_status)
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

    def _release(self):
        """Releases storage backing this OIDSet. After calling this method,
        this OIDSet can no longer be used."""
        if hasattr(self, '_oid_set') and self._oid_set:
            minor_status = OM_uint32()
            gss_release_oid_set(byref(minor_status), byref(self._oid_set))
            self._oid_set = cast(GSS_C_NO_OID_SET, gss_OID_set)

    def __del__(self):
        self._release()


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
        if self._oid_set:
            if isinstance(new_oid, OID):
                oid_ptr = byref(new_oid._oid)
            elif isinstance(new_oid, gss_OID_desc):
                oid_ptr = byref(new_oid)
            elif isinstance(new_oid, gss_OID):
                oid_ptr = new_oid
            else:
                raise TypeError("Expected an OID, got " + str(type(new_oid)))

            minor_status = OM_uint32()
            retval = gss_add_oid_set_member(byref(minor_status), oid_ptr, byref(self._oid_set))
            if retval != GSS_S_COMPLETE:
                raise GSSCException(retval, minor_status)
