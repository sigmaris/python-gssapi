import base64
import logging
import socket
import sys
import unittest

from gssapi import (InitContext, Name, Credential, C_NT_HOSTBASED_SERVICE, C_CONF_FLAG,
                    C_INTEG_FLAG, C_DELEG_FLAG, C_INITIATE)

logging.basicConfig()


class ClientIntegrationTest(unittest.TestCase):

    def setUp(self):
        self.sock, self.sockfile = self._connect()

    def tearDown(self):
        self.sockfile.close()
        self.sock.close()

    def _writeline(self, line):
        self.sock.sendall(line)
        self.sock.sendall(b'\n')

    @classmethod
    def _connect(cls):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("server.pythongssapi.test", 10100 + sys.version_info[0]))
        sockfile = s.makefile('rwb')
        return s, sockfile

    @classmethod
    def _handshake(cls, sockfile, ctx):
        in_token = None
        while not ctx.established:
            out_token = ctx.step(in_token)
            out_b64 = base64.b64encode(out_token)
            sockfile.write(out_b64)
            sockfile.write(b'\n')
            sockfile.flush()
            in_token = sockfile.readline()
            if ctx.established:
                if in_token.strip() == b'!OK':
                    break
                else:
                    raise RuntimeError("Server did not report successful handshake")
            else:
                in_token = base64.b64decode(in_token)

    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger(__name__)

    @classmethod
    def tearDownClass(cls):
         cls.logger.info("*** client starting shutdown ***")
         sock, sockfile = cls._connect()
         ctx = InitContext(Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE))
         cls._handshake(sockfile, ctx)
         cls.logger.info("*** client sending SHUTDOWN command ***")
         sockfile.write(b'!SHUTDOWN\n')
         sockfile.close()
         sock.close()

    def test_basic_handshake(self):
        ctx = InitContext(Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE))
        self._handshake(self.sockfile, ctx)
        self._writeline(b'!MYNAME')
        self.assertEqual(self.sockfile.readline().strip(), b'testuser@PYTHONGSSAPI.TEST')

    def test_lifetime(self):
        ctx = InitContext(Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE))
        self._handshake(self.sockfile, ctx)
        self._writeline(b'!LIFETIME')
        self.assertLess(abs(int(self.sockfile.readline().strip()) - ctx.lifetime), 5)

    def test_wrapping(self):
        ctx = InitContext(
            Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE),
            req_flags=(C_CONF_FLAG,)
        )
        self._handshake(self.sockfile, ctx)
        assert ctx.confidentiality_negotiated
        self._writeline(b'!WRAPTEST')
        self._writeline(base64.b64encode(ctx.wrap(b'msg_from_client')))
        self.assertEqual(self.sockfile.readline().strip(), b'!OK')
        self.assertEqual(ctx.unwrap(base64.b64decode(self.sockfile.readline())), b'msg_from_server')

    def test_mic(self):
        ctx = InitContext(
            Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE),
            req_flags=(C_INTEG_FLAG,)
        )
        self._handshake(self.sockfile, ctx)
        assert ctx.integrity_negotiated
        self._writeline(b'!MICTEST')
        self._writeline(b'msg_from_client')
        self._writeline(base64.b64encode(ctx.get_mic(b'msg_from_client')))
        self.assertEqual(self.sockfile.readline().strip(), b'!OK')
        self.assertEqual(self.sockfile.readline().strip(), b'msg_from_server')
        ctx.verify_mic(b'msg_from_server', base64.b64decode(self.sockfile.readline()))

    def test_get_wrap_size_limit(self):
        ctx = InitContext(
            Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE),
            req_flags=(C_CONF_FLAG,)
        )
        self._handshake(self.sockfile, ctx)
        assert ctx.confidentiality_negotiated
        wrap_size_limit = ctx.get_wrap_size_limit(512)
        self.assertLessEqual(wrap_size_limit, 512)
        msg = b'*' * wrap_size_limit
        self.assertLessEqual(len(ctx.wrap(msg)), 512)
        self._writeline(b'!NOOP')

    def test_deleg_cred(self):
        cred = Credential(usage=C_INITIATE)
        ctx = InitContext(
            Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE),
            cred,
            req_flags=(C_DELEG_FLAG,)
        )
        self._handshake(self.sockfile, ctx)
        self._writeline(b'!DELEGTEST')
        self.assertEqual(self.sockfile.readline().strip(), b'!OK')
        self.assertEqual(self.sockfile.readline().strip(), b'testuser@PYTHONGSSAPI.TEST')
        self.assertLess(abs(int(self.sockfile.readline().strip()) - cred.lifetime), 5)

    def test_no_deleg_cred(self):
        ctx = InitContext(Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE))
        self._handshake(self.sockfile, ctx)
        self._writeline(b'!DELEGTEST')
        self.assertEqual(self.sockfile.readline().strip(), b'!NOCRED')

    def test_mech_type(self):
        ctx = InitContext(Name("host@server.pythongssapi.test", C_NT_HOSTBASED_SERVICE))
        self._handshake(self.sockfile, ctx)
        self._writeline(b'!MECHTYPE')
        self.assertEqual(self.sockfile.readline().strip().decode('utf-8'), str(ctx.mech_type))
