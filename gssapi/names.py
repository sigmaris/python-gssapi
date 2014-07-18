from __future__ import absolute_import

import six

from .bindings import C, ffi, GSS_ERROR, _buf_to_str
from .error import GSSException, _exception_for_status
from .oids import OID


def _release_gss_name_t(name):
    if name[0]:
        C.gss_release_name(ffi.new('OM_uint32[1]'), name)


class _NameMeta(type):
    # Creates a MechName if a GSS_C_NT_EXPORT_NAME is imported
    def __call__(cls, *args, **kwargs):
        if 'name_type' in kwargs:
            name_type = kwargs['name_type']
        elif len(args) > 1:
            name_type = args[1]
        else:
            name_type = None
        if name_type == C.GSS_C_NT_EXPORT_NAME:
            mech_name = MechName(None, C.GSS_C_NO_OID)
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

    def __init__(self, name, name_type=C.GSS_C_NO_OID):
        super(Name, self).__init__()

        if isinstance(name, ffi.CData) and ffi.typeof(name) == ffi.typeof('gss_name_t[1]'):
            # Break out early, used for internal name construction without import
            self._name = ffi.gc(name, _release_gss_name_t)  # take ownership for GC purposes
            return
        else:
            self._name = ffi.new('gss_name_t[1]')
            self._import_name(name, name_type)

    def _import_name(self, name, name_type):
        minor_status = ffi.new('OM_uint32[1]')

        name_buffer = ffi.new('gss_buffer_desc[1]')
        if isinstance(name, bytes):
            name_buffer[0].length = len(name)
            c_str_name = ffi.new('char[]', name)
            name_buffer[0].value = c_str_name
        elif isinstance(name, six.string_types):
            name_bytes = name.encode()
            name_buffer[0].length = len(name_bytes)
            c_str_name = ffi.new('char[]', name_bytes)
            name_buffer[0].value = c_str_name
        elif isinstance(name, six.integer_types):
            c_name = ffi.new('uid_t[1]', (name,))
            name_buffer[0].length = ffi.sizeof('uid_t')
            name_buffer[0].value = c_name
        else:
            raise TypeError("Expected a string or integer, got {0}".format(type(name)))

        if isinstance(name_type, OID):
            name_type = ffi.addressof(name_type._oid)
        elif name_type == C.GSS_C_NO_OID:
            name_type = ffi.cast('gss_OID', name_type)
        elif not isinstance(name_type, ffi.CData) or ffi.typeof(name_type) != ffi.typeof('gss_OID'):
            raise TypeError("Expected an OID or GSS_C_NT_* constant, got {0}".format(type(name_type)))

        retval = C.gss_import_name(
            minor_status, name_buffer, name_type, self._name
        )
        self._name = ffi.gc(self._name, _release_gss_name_t)
        if GSS_ERROR(retval):
            raise _exception_for_status(retval, minor_status[0])

    def __str__(self):
        return self._display().decode()

    @property
    def type(self):
        """
        An :class:`~gssapi.oids.OID` representing this name's type.
        """
        return self._display(with_type=True)[1]

    def _display(self, with_type=False):
        minor_status = ffi.new('OM_uint32[1]')
        out_buffer = ffi.new('gss_buffer_desc[1]')
        if with_type:
            output_name_type = ffi.new('gss_OID[1]')
        else:
            output_name_type = ffi.NULL

        try:
            retval = C.gss_display_name(
                minor_status, self._name[0], out_buffer, output_name_type
            )
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])
            if with_type:
                return _buf_to_str(out_buffer[0]), OID(output_name_type[0][0])
            else:
                return _buf_to_str(out_buffer[0])
        finally:
            if out_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, out_buffer)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        if isinstance(other, Name):
            minor_status = ffi.new('OM_uint32[1]')
            name_equal = ffi.new('int[1]')
            retval = C.gss_compare_name(
                minor_status,
                self._name[0],
                other._name[0],
                name_equal
            )
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])
            return bool(name_equal[0])
        else:
            return False

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

        minor_status = ffi.new('OM_uint32[1]')
        out_name = ffi.new('gss_name_t[1]')
        try:
            retval = C.gss_canonicalize_name(
                minor_status, self._name[0], ffi.addressof(oid), out_name
            )
            if GSS_ERROR(retval):
                raise _exception_for_status(retval, minor_status[0])
            return MechName(out_name, mech)
        except:
            C.gss_release_name(minor_status, out_name)

# Add metaclass in Python 2/3 compatible way:
Name = six.add_metaclass(_NameMeta)(Name)


class MechName(Name):
    """
    Represents a GSSAPI Mechanism Name (MN) as obtained by
    :meth:`~gssapi.names.Name.canonicalize` or as the
    :attr:`~gssapi.ctx.AcceptContext.peer_name` property of an :class:`~gssapi.ctx.AcceptContext`.

    Don't construct instances of this class directly; use
    :meth:`~gssapi.names.Name.canonicalize` on a :class:`Name` to create a :class:`MechName`.
    """

    def __init__(self, name, mech_type):
        """Don't construct instances of this class directly; This object will acquire
        ownership of `name`, and release the associated storage when it is deleted."""
        if isinstance(name, ffi.CData) and ffi.typeof(name) == ffi.typeof('gss_name_t[1]'):
            self._name = ffi.gc(name, _release_gss_name_t)
        else:
            self._name = ffi.new('gss_name_t[1]')
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
        minor_status = ffi.new('OM_uint32[1]')
        output_buffer = ffi.new('gss_buffer_desc[1]')
        retval = C.gss_export_name(
            minor_status,
            self._name[0],
            output_buffer
        )
        try:
            if GSS_ERROR(retval):
                if minor_status[0] and self._mech_type:
                    raise _exception_for_status(retval, minor_status[0], self._mech_type)
                else:
                    raise _exception_for_status(retval, minor_status[0])

            return _buf_to_str(output_buffer[0])
        finally:
            if output_buffer[0].length != 0:
                C.gss_release_buffer(minor_status, output_buffer)
