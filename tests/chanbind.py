from __future__ import absolute_import

import socket
import unittest

import gssapi
from gssapi.bindings import _buf_to_str


class ChannelBindingsTestCase(unittest.TestCase):

    def test_generic_bindings(self):
        cb = gssapi.ChannelBindings(gssapi.C_AF_LOCAL, b'test initiator address',
                                    gssapi.C_AF_LOCAL, b'test acceptor address', b'test app data')
        self.assertEqual(cb._cb.initiator_addrtype, gssapi.C_AF_LOCAL)
        self.assertEqual(_buf_to_str(cb._cb.initiator_address), b'test initiator address')
        self.assertEqual(cb._cb.acceptor_addrtype, gssapi.C_AF_LOCAL)
        self.assertEqual(_buf_to_str(cb._cb.acceptor_address), b'test acceptor address')
        self.assertEqual(_buf_to_str(cb._cb.application_data), b'test app data')

    def test_app_data_only(self):
        cb = gssapi.ChannelBindings(application_data=b'test app data')
        self.assertEqual(cb._cb.initiator_addrtype, gssapi.C_AF_NULLADDR)
        self.assertEqual(_buf_to_str(cb._cb.initiator_address), b'')
        self.assertEqual(cb._cb.acceptor_addrtype, gssapi.C_AF_NULLADDR)
        self.assertEqual(_buf_to_str(cb._cb.acceptor_address), b'')
        self.assertEqual(_buf_to_str(cb._cb.application_data), b'test app data')

    def test_ipv4_bindings(self):
        cb = gssapi.IPv4ChannelBindings('192.168.2.3', '192.168.4.5')
        self.assertEqual(cb._cb.initiator_addrtype, gssapi.C_AF_INET)
        self.assertEqual(cb._cb.acceptor_addrtype, gssapi.C_AF_INET)
        self.assertEqual(_buf_to_str(cb._cb.initiator_address), socket.inet_aton('192.168.2.3'))
        self.assertEqual(_buf_to_str(cb._cb.acceptor_address), socket.inet_aton('192.168.4.5'))

    def test_ipv6_bindings(self):
        if not hasattr(gssapi, 'IPv6ChannelBindings'):
            self.skipTest("Implementation doesn't support GSS_C_AF_INET6")
        else:
            cb = gssapi.IPv6ChannelBindings(
                '2a00:1450:4009:804::1011',
                '2a03:2880:2110:3f07:face:b00c:0:1'
            )
            self.assertEqual(cb._cb.initiator_addrtype, gssapi.C_AF_INET6)
            self.assertEqual(cb._cb.acceptor_addrtype, gssapi.C_AF_INET6)
            self.assertEqual(
                _buf_to_str(cb._cb.initiator_address),
                socket.inet_pton(socket.AF_INET6, '2a00:1450:4009:804::1011')
            )
            self.assertEqual(
                _buf_to_str(cb._cb.acceptor_address),
                socket.inet_pton(socket.AF_INET6, '2a03:2880:2110:3f07:face:b00c:0:1')
            )
