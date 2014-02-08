import logging
import socket
import unittest

from gssapi import InitContext, Name, C_NT_HOSTBASED_SERVICE

logging.basicConfig()


class ClientIntegrationTest(unittest.TestCase):

    def setUp(self):
        self.sock, self.sockfile = self._connect()

    def tearDown(self):
        self.sockfile.close()
        self.sock.close()

    @classmethod
    def _connect(cls):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("server.pythongssapi.test", 59991))
        sockfile = s.makefile('rwb')
        return s, sockfile

    @classmethod
    def _handshake(cls, sockfile, ctx):
        in_token = None
        while not ctx.established:
            sockfile.write(ctx.step(in_token).encode('base64'))
            in_token = sockfile.readline()
            if ctx.established:
                if in_token.strip() == '+OK':
                    break
                else:
                    raise RuntimeError("Server did not report successful handshake")
            else:
                in_token = in_token.decode('base64')

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
        sockfile.write("+SHUTDOWN\n")
        sockfile.close()
        sock.close()

    def test_foobar(self):
        assert True
