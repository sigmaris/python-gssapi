from __future__ import absolute_import

import numbers

from ctypes import byref, cast, c_char_p, c_void_p, c_int, string_at, sizeof, pointer

from .headers.gssapi_h import (
    GSS_C_NO_OID, GSS_C_NO_NAME, GSS_S_COMPLETE, GSS_ERROR, GSS_C_NT_USER_NAME,
    GSS_C_NT_EXPORT_NAME,
    OM_uint32, gss_buffer_desc, gss_name_t, gss_OID,
    gss_import_name, gss_display_name, gss_canonicalize_name,
    gss_compare_name, gss_export_name, gss_release_name, gss_release_buffer,
    uid_t
)
from .error import GSSCException, GSSException, GSSMechException, _buf_to_str
from .oids import OID


class _NameMeta(type):
    # Creates a MechName if a GSS_C_NT_EXPORT_NAME is imported
    def __call__(cls, *args, **kwargs):
        if 'name_type' in kwargs:
            name_type = kwargs['name_type']
        elif len(args) > 1:
            name_type = args[1]
        else:
            name_type = None
        if name_type == GSS_C_NT_EXPORT_NAME:
            mech_name = MechName(gss_name_t(), GSS_C_NO_OID)
            mech_name._import_name(*args, **kwargs)
            return mech_name
        else:
            return super(_NameMeta, cls).__call__(*args, **kwargs)


class Name(object):
    """
    Used to construct GSSAPI internal-form names from a string representation (or numeric UID on
    POSIX platforms).

    :param name: The string or numeric UID representing the name
    :type name: string or int
    :param name_type: A constant identifying the type of name represented by the `name` param, e.g.
        :const:`gssapi.C_NT_USER_NAME` or :const:`gssapi.C_NT_HOSTBASED_SERVICE`.
    :type name_type: `gssapi.C_NT_*` constant or :class:`~gssapi.oids.OID`
    """
    __metaclass__ = _NameMeta

    def __init__(self, name, name_type=GSS_C_NO_OID):
        super(Name, self).__init__()

        if type(name) == gss_name_t:
            # Break out early, used for internal name construction without import
            self._name = name
            return
        else:
            self._name = gss_name_t()
            self._import_name(name, name_type)

    def _import_name(self, name, name_type):
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

        if isinstance(name_type, OID):
            name_type = byref(name_type._oid)
        elif type(name_type) == type(GSS_C_NT_USER_NAME) or name_type == GSS_C_NO_OID:
            name_type = cast(name_type, gss_OID)
        else:
            raise TypeError("Expected an OID or GSS_C_NT_* constant, got {0}".format(type(name_type)))

        retval = gss_import_name(
            byref(minor_status), byref(name_buffer), name_type, byref(self._name)
        )
        if retval != GSS_S_COMPLETE:
            self._release()
            raise GSSCException(retval, minor_status)

    def __str__(self):
        return self._display()

    @property
    def type(self):
        """
        An :class:`~gssapi.oids.OID` representing this name's type.
        """
        return self._display(with_type=True)[1]

    def _display(self, with_type=False):
        minor_status = OM_uint32()
        out_buffer = gss_buffer_desc()
        if with_type:
            output_name_type = gss_OID()
            output_name_type_param = byref(output_name_type)
        else:
            output_name_type = None
            output_name_type_param = None

        try:
            retval = gss_display_name(
                byref(minor_status), self._name, byref(out_buffer), output_name_type_param
            )
            if retval != GSS_S_COMPLETE:
                raise GSSCException(retval, minor_status)
            if with_type:
                return _buf_to_str(out_buffer), OID(output_name_type.contents)
            else:
                return _buf_to_str(out_buffer)
        finally:
            gss_release_buffer(byref(minor_status), byref(out_buffer))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        if isinstance(other, Name):
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
        if hasattr(self, '_name') and self._name:
            minor_status = OM_uint32()
            gss_release_name(byref(minor_status), byref(self._name))
            self._name = cast(GSS_C_NO_NAME, gss_name_t)

    def canonicalize(self, mech):
        """
        Create a canonical mechanism name (MechName) from an arbitrary internal name. The canonical
        MechName would be set as the :attr:`~gssapi.ctx.AcceptContext.peer_name` property on an
        acceptor's :class:`~gssapi.ctx.AcceptContext` if an initiator performed a successful
        authentication to the acceptor using the given mechanism, using a
        :class:`~gssapi.creds.Credential` obtained using this :class:`Name`.

        :param mech: The mechanism to canonicalize this name for
        :type mech: :class:`~gssapi.oids.OID`
        :returns: a canonical mechanism name based on this internal name.
        :rtype: :class:`MechName`
        """
        if isinstance(mech, OID):
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


class MechName(Name):
    """
    Represents a GSSAPI Mechanism Name (MN) as obtained by
    :meth:`~gssapi.names.Name.canonicalize` or as the
    :attr:`~gssapi.ctx.AcceptContext.peer_name` property of an :class:`~gssapi.ctx.AcceptContext`.

    Don't construct instances of this class directly; use
    :meth:`~gssapi.names.Name.canonicalize` on a :class:`Name` to create a `MechName`.
    """

    def __init__(self, name, mech_type):
        """Don't construct instances of this class directly; This object will acquire
        ownership of 'name', and release the associated storage when it is deleted."""
        self._name = name
        self._mech_type = mech_type

    def canonicalize(self, mech):
        raise GSSException("Can't canonicalize a mechanism name.")

    def export(self):
        """
        Returns a representation of the Mechanism Name which is suitable for direct string
        comparison against other exported Mechanism Names. Its form is defined in the GSSAPI
        specification (RFC 2743). It can also be re-imported by constructing a :class:`Name` with
        the `name_type` param set to :const:`gssapi.C_NT_EXPORT_NAME`.

        :returns: an exported bytestring representation of this mechanism name
        :rtype: bytes
        """
        minor_status = OM_uint32()
        output_buffer = gss_buffer_desc()
        retval = gss_export_name(
            byref(minor_status),
            self._name,
            byref(output_buffer)
        )
        try:
            if GSS_ERROR(retval):
                if minor_status and self._mech_type:
                    raise GSSMechException(retval, minor_status, self._mech_type)
                else:
                    raise GSSCException(retval, minor_status)

            output = string_at(output_buffer.value, output_buffer.length)
            return output
        finally:
            if output_buffer.length != 0:
                gss_release_buffer(byref(minor_status), byref(output_buffer))
