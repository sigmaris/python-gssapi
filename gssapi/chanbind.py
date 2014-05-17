from __future__ import absolute_import

import socket

from .bindings import C, ffi, _buf_to_str


class ChannelBindings(object):
    """
    Represents channel bindings that identify the initiator and acceptor of a security context.
    This class is a generic one that can be subclassed to provide channel bindings for specific
    address types.

    :param initiator_addrtype: One of the ``gssapi.C_AF_*`` constants representing the address type
        of the initiator address.
    :param initiator_address: The initiator address, in whatever format the address type requires.
        Normally this would be a binary format in network byte order, e.g a ``struct in_addr`` for
        :data:`~gssapi.C_AF_INET`.
    :type initiator_address: bytes
    :param acceptor_addrtype: One of the ``gssapi.C_AF_*`` constants representing the address type
        of the acceptor address.
    :param acceptor_address: The acceptor address, in whatever format the address type requires.
    :type acceptor_address: bytes
    :param application_data: An optional application-defined token to include in channel bindings.
    :type application_data: bytes


    The parameters `initiator_addrtype`, `application_data`, etc, can also be set as attributes on
    instances of this class.
    """

    def __init__(self, initiator_addrtype=C.GSS_C_AF_NULLADDR, initiator_address=None,
                 acceptor_addrtype=C.GSS_C_AF_NULLADDR, acceptor_address=None,
                 application_data=None):
        super(ChannelBindings, self).__init__()
        self._cb = ffi.new('gss_channel_bindings_t')
        self.initiator_addrtype = initiator_addrtype
        self.initiator_address = initiator_address
        self.acceptor_addrtype = acceptor_addrtype
        self.acceptor_address = acceptor_address
        self.application_data = application_data

    @property
    def initiator_addrtype(self):
        return self._cb.initiator_addrtype

    @initiator_addrtype.setter
    def initiator_addrtype(self, addrtype):
        self._cb.initiator_addrtype = addrtype

    @property
    def initiator_address(self):
        return _buf_to_str(self._cb.initiator_address)

    @initiator_address.setter
    def initiator_address(self, address):
        if address is not None and len(address) > 0:
            self._cb.initiator_address.length = len(address)
            self.c_str_initiator_address = ffi.new('char[]', address)
            self._cb.initiator_address.value = self.c_str_initiator_address
        else:
            self._cb.initiator_address.length = 0
            self.c_str_initiator_address = None
            self._cb.initiator_address.value = ffi.NULL

    @property
    def acceptor_addrtype(self):
        return self._cb.acceptor_addrtype

    @acceptor_addrtype.setter
    def acceptor_addrtype(self, addrtype):
        self._cb.acceptor_addrtype = addrtype

    @property
    def acceptor_address(self):
        return _buf_to_str(self._cb.acceptor_address)

    @acceptor_address.setter
    def acceptor_address(self, address):
        if address is not None and len(address) > 0:
            self._cb.acceptor_address.length = len(address)
            self.c_str_acceptor_address = ffi.new('char[]', address)
            self._cb.acceptor_address.value = self.c_str_acceptor_address
        else:
            self._cb.acceptor_address.length = 0
            self.c_str_acceptor_address = None
            self._cb.acceptor_address.value = ffi.NULL

    @property
    def application_data(self):
        return _buf_to_str(self._cb.application_data)

    @application_data.setter
    def application_data(self, data):
        if data is not None and len(data) > 0:
            self._cb.application_data.length = len(data)
            self.c_str_application_data = ffi.new('char[]', data)
            self._cb.application_data.value = self.c_str_application_data
        else:
            self._cb.application_data.length = 0
            self.c_str_application_data = None
            self._cb.application_data.value = ffi.NULL


class IPv4ChannelBindings(ChannelBindings):
    """
    Represents channel bindings using IPv4 initiator and/or acceptor addresses.
    Note that using IP addresses in GSSAPI channel bindings is deprecated and does not work across
    NAT. However this class may be useful if implementing an application protocol that requires
    IP channel bindings, like FTP with GSSAPI authentication.

    :param initiator_address: The initiator address in dotted-decimal format, e.g. "10.0.0.1"
    :type initiator_address: str
    :param acceptor_address: The acceptor address in dotted-decimal format, e.g. "10.0.0.1"
    :type acceptor_address: str
    """

    def __init__(self, initiator_address=None, acceptor_address=None):
        kwargs = {}
        if initiator_address is not None:
            kwargs['initiator_addrtype'] = C.GSS_C_AF_INET
            kwargs['initiator_address'] = socket.inet_aton(initiator_address)
        if acceptor_address is not None:
            kwargs['acceptor_addrtype'] = C.GSS_C_AF_INET
            kwargs['acceptor_address'] = socket.inet_aton(acceptor_address)
        super(IPv4ChannelBindings, self).__init__(**kwargs)


if hasattr(C, 'GSS_C_AF_INET6'):

    class IPv6ChannelBindings(ChannelBindings):
        """
        Represents channel bindings using IPv6 initiator and/or acceptor addresses.
        Note that using IP addresses in GSSAPI channel bindings is deprecated and does not work
        across NAT. However this class may be useful if implementing an application protocol that
        requires IP channel bindings, like FTP with GSSAPI authentication. This class will only be
        available if the underlying implementation defines the address type `GSS_C_AF_INET6`.

        :param initiator_address: The initiator address in colon-separated format,
            e.g. "2001:db8::ff00:42:8329"
        :type initiator_address: str
        :param acceptor_address: The acceptor address in colon-separated format.
        :type acceptor_address: str
        """


        def __init__(self, initiator_address=None, acceptor_address=None):
            kwargs = {}
            if initiator_address is not None:
                kwargs['initiator_addrtype'] = C.GSS_C_AF_INET6
                kwargs['initiator_address'] = socket.inet_pton(socket.AF_INET6, initiator_address)
            if acceptor_address is not None:
                kwargs['acceptor_addrtype'] = C.GSS_C_AF_INET6
                kwargs['acceptor_address'] = socket.inet_pton(socket.AF_INET6, acceptor_address)
            super(IPv6ChannelBindings, self).__init__(**kwargs)
