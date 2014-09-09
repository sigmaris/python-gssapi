import base64
import platform
import sys
import tempfile

import six
if six.PY3:
    import socketserver
else:
    import SocketServer as socketserver

from gssapi import AcceptContext, Credential, C_INITIATE, S_DUPLICATE_TOKEN, S_GAP_TOKEN, S_UNSEQ_TOKEN


class AddressReusingServer(socketserver.ThreadingTCPServer):

    allow_reuse_address = True


class GSSAPIHandler(socketserver.BaseRequestHandler):

    def _writeline(self, line):
        self.request.sendall(line)
        self.request.sendall(b'\n')

    def handle(self):
        global server
        print("{0} connected".format(self.client_address[0]))
        ctx = AcceptContext()
        self.sockfile = self.request.makefile('rwb')
        while not ctx.established:
            print("{0} handshaking...".format(self.client_address[0]))
            in_b64 = self.sockfile.readline()
            in_token = base64.b64decode(in_b64)
            print("{0} sent {1} bytes.".format(self.client_address[0], len(in_token)))
            if len(in_token) < 1:
                return
            out_token = ctx.step(in_token)
            if out_token:
                print("Sending back {0} bytes".format(len(out_token)))
                self._writeline(base64.b64encode(out_token))
        print("{0} handshake complete.".format(self.client_address[0]))
        self._writeline(b'!OK')
        client_command = self.sockfile.readline().strip()
        print("{0} command: {1}".format(self.client_address[0], client_command))

        if client_command[0] != b'!'[0]:
            self._writeline(b'!ERROR')
            print("That wasn't a command, closing connection")
            return

        if client_command == b'!SHUTDOWN':
            server.shutdown()
        elif client_command == b'!MYNAME':
            self._writeline(six.text_type(ctx.peer_name).encode('utf-8'))
        elif client_command == b'!LIFETIME':
            self._writeline(six.text_type(ctx.lifetime).encode('utf-8'))
        elif client_command == b'!WRAPTEST':
            self._wrap_test(ctx)
        elif client_command == b'!MICTEST':
            self._mic_test(ctx)
        elif client_command == b'!DELEGTEST':
            self._delegated_cred_test(ctx)
        elif client_command == b'!DELEGSTORE':
            self._delegated_cred_store_test(ctx)
        elif client_command == b'!MECHTYPE':
            self._writeline(six.text_type(ctx.mech_type).encode('utf-8'))
        elif client_command == b'!REPLAYTEST':
            self._replay_test(ctx)
        elif client_command == b'!GAPTEST':
            self._gap_test(ctx)
        elif client_command == b'!UNSEQTEST':
            self._unseq_test(ctx)

    def _wrap_test(self, ctx):
        if not ctx.confidentiality_negotiated:
            print("WRAPTEST: no confidentiality_negotiated")
            self._writeline(b'!ERROR')
            return
        try:
            unwrapped = ctx.unwrap(base64.b64decode(self.sockfile.readline()))
        except:
            self._writeline(b'!ERROR')
            raise
        if unwrapped != b'msg_from_client':
            print("WRAPTEST: no msg_from_client")
            self._writeline(b'!ERROR')
            return
        self._writeline(b'!OK')
        self._writeline(base64.b64encode(ctx.wrap(b'msg_from_server')))

    def _mic_test(self, ctx):
        if not ctx.integrity_negotiated:
            print("MICTEST: no integrity_negotiated")
            self._writeline(b'!ERROR')
            return
        msg = self.sockfile.readline().strip()
        mic = base64.b64decode(self.sockfile.readline())
        try:
            ctx.verify_mic(msg, mic)
        except:
            self._writeline(b'!ERROR')
            raise
        if msg != b'msg_from_client':
            print("MICTEST: no msg_from_client")
            self._writeline(b'!ERROR')
            return
        self._writeline(b'!OK')
        self._writeline(b'msg_from_server')
        self._writeline(base64.b64encode(ctx.get_mic(b'msg_from_server')))

    def _delegated_cred_test(self, ctx):
        if ctx.delegated_cred:
            self._writeline(b'!OK')
            self._writeline(six.text_type(ctx.delegated_cred.name).encode('utf-8'))
            self._writeline(six.text_type(ctx.delegated_cred.lifetime).encode('utf-8'))
        else:
            self._writeline(b'!NOCRED')

    def _delegated_cred_store_test(self, ctx):
        if ctx.delegated_cred:
            # Create the default ccache as a side-effect
            str(Credential(usage=C_INITIATE, cred_store={'client_keytab':'/etc/krb5.keytab'}).name)
            # Store delegated cred in default ccache
            ctx.delegated_cred.store(default=True, overwrite=True)
            # Store again, in non-default ccache
            ctx.delegated_cred.store(default=True, overwrite=True,
                                     cred_store={'ccache': 'FILE:{0}'.format(tempfile.mktemp())})
            self._writeline(b'!OK')
        else:
            self._writeline(b'!NOCRED')

    def _replay_test(self, ctx):
        if not ctx.replay_detection_negotiated:
            print("REPLAYTEST: no replay_detection_negotiated")
            self._writeline(b'!ERROR')
            return
        # Client should send message 1, message 2, then replayed message 1
        try:
            msg1 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
            msg2 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
            msg3 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
        except:
            self._writeline(b'!ERROR')
            raise
        for msg, expected, flag in (
            (msg1, b'msg_from_client1', None),
            (msg2, b'msg_from_client2', None),
            (msg3, b'msg_from_client1', S_DUPLICATE_TOKEN)
        ):
            if msg[0] != expected or (flag and flag not in msg[1]):
                print("REPLAYTEST: unexpected message {0!r}".format(msg))
                self._writeline(b'!ERROR')
                return
        # Server sends message 1, message 2, then replayed message 1
        msg1 = ctx.wrap(b'msg_from_server1')
        msg2 = ctx.wrap(b'msg_from_server2')
        self._writeline(base64.b64encode(msg1))
        self._writeline(base64.b64encode(msg2))
        self._writeline(base64.b64encode(msg1))

    def _gap_test(self, ctx):
        if not ctx.sequence_detection_negotiated:
            print("GAPTEST: no sequence_detection_negotiated")
            self._writeline(b'!ERROR')
            return
        if not ctx.replay_detection_negotiated:
            print("GAPTEST: no replay_detection_negotiated")
            self._writeline(b'!ERROR')
            return
        # Client should wrap message 1, message 2, message 3, then only send msg 1 and 3
        try:
            msg1 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
            msg2 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
        except:
            self._writeline(b'!ERROR')
            raise
        for msg, expected, flag in (
            (msg1, b'msg_from_client1', None),
            (msg2, b'msg_from_client3', S_GAP_TOKEN),
        ):
            if msg[0] != expected or (flag and flag not in msg[1]):
                print("GAPTEST: unexpected message {0!r}".format(msg))
                self._writeline(b'!ERROR')
                return
        # Server wraps message 1, message 2, message 3, then only sends msg 1 and 3
        msg1 = ctx.wrap(b'msg_from_server1')
        msg2 = ctx.wrap(b'msg_from_server2')
        msg3 = ctx.wrap(b'msg_from_server3')
        self._writeline(base64.b64encode(msg1))
        self._writeline(base64.b64encode(msg3))

    def _unseq_test(self, ctx):
        if not ctx.sequence_detection_negotiated:
            print("UNSEQTEST: no sequence_detection_negotiated")
            self._writeline(b'!ERROR')
            return
        # Client should wrap message 1, message 2, message 3, then send msg 1, 3, 2
        try:
            msg1 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
            msg2 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
            msg3 = ctx.unwrap(base64.b64decode(self.sockfile.readline()), supplementary=True)
        except:
            self._writeline(b'!ERROR')
            raise
        for msg, expected, flag in (
            (msg1, b'msg_from_client1', None),
            (msg2, b'msg_from_client3', None),
            (msg3, b'msg_from_client2', S_UNSEQ_TOKEN),
        ):
            if msg[0] != expected or (flag and flag not in msg[1]):
                print("UNSEQTEST: unexpected message {0!r}".format(msg))
                self._writeline(b'!ERROR')
                return
        # Server wraps message 1, message 2, message 3, then sends msg 1, 3, 2
        msg1 = ctx.wrap(b'msg_from_server1')
        msg2 = ctx.wrap(b'msg_from_server2')
        msg3 = ctx.wrap(b'msg_from_server3')
        self._writeline(base64.b64encode(msg1))
        self._writeline(base64.b64encode(msg3))
        self._writeline(base64.b64encode(msg2))


if __name__ == '__main__':
    if platform.python_implementation().lower() == 'pypy':
        base_port = 10200
    else:
        base_port = 10100
    server = AddressReusingServer(('', base_port + sys.version_info[0]), GSSAPIHandler)
    print("Starting test server...")
    server.serve_forever()
    print("Test server shutdown.")
