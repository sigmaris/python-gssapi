import base64
import SocketServer

from gssapi import AcceptContext


class GSSAPIHandler(SocketServer.BaseRequestHandler):

    def _writeline(self, line):
        self.request.sendall(line + b'\n')

    def handle(self):
        global server
        print("{0} connected".format(self.client_address[0]))
        ctx = AcceptContext()
        self.sockfile = self.request.makefile('rwb')
        while not ctx.established:
            print("{0} handshaking...".format(self.client_address[0]))
            in_b64 = self.sockfile.readline()
            in_token = base64.b64decode(in_b64)
            print("{0} sent {1} bytes.").format(self.client_address[0], len(in_token))
            if len(in_token) < 1:
                return
            out_token = ctx.step(in_token)
            if out_token:
                print("Sending back {0} bytes".format(len(out_token)))
                self._writeline(base64.b64encode(out_token))
        print("{0} handshake complete.".format(self.client_address[0]))
        self._writeline('!OK')
        client_command = self.sockfile.readline().strip()
        print("{0} command: {1}".format(self.client_address[0], client_command))

        if client_command[0] != '!':
            self._writeline(b'!ERROR')
            print("That wasn't a command, closing connection")
            return

        if client_command == '!SHUTDOWN':
            server.shutdown()
        elif client_command == '!MYNAME':
            self._writeline(str(ctx.peer_name))
        elif client_command == '!WRAPTEST':
            self._wrap_test(ctx)
        elif client_command == '!MICTEST':
            self._mic_test(ctx)
        elif client_command == '!DELEGTEST':
            self._delegated_cred_test(ctx)
        elif client_command == '!MECHTYPE':
            self._writeline(str(ctx.mech_type))

    def _wrap_test(self, ctx):
        if not ctx.confidentiality_negotiated:
            print("WRAPTEST: no confidentiality_negotiated")
            self._writeline('!ERROR')
            return
        try:
            unwrapped = ctx.unwrap(base64.b64decode(self.sockfile.readline()))
        except:
            self._writeline('!ERROR')
            raise
        if unwrapped != 'msg_from_client':
            print("WRAPTEST: no msg_from_client")
            self._writeline('!ERROR')
            return
        self._writeline('!OK')
        self._writeline(base64.b64encode(ctx.wrap('msg_from_server')))

    def _mic_test(self, ctx):
        if not ctx.integrity_negotiated:
            print("MICTEST: no integrity_negotiated")
            self._writeline('!ERROR')
            return
        msg = self.sockfile.readline().strip()
        mic = base64.b64decode(self.sockfile.readline())
        try:
            ctx.verify_mic(msg, mic)
        except:
            self._writeline('!ERROR')
            raise
        if msg != 'msg_from_client':
            print("MICTEST: no msg_from_client")
            self._writeline('!ERROR')
            return
        self._writeline('!OK')
        self._writeline('msg_from_server')
        self._writeline(base64.b64encode(ctx.get_mic('msg_from_server')))

    def _delegated_cred_test(self, ctx):
        if ctx.delegated_cred:
            self._writeline('!OK')
            self._writeline(str(ctx.delegated_cred.name))
            self._writeline(str(ctx.delegated_cred.lifetime))
        else:
            self._writeline('!NOCRED')


if __name__ == '__main__':
    server = SocketServer.ThreadingTCPServer(('', 59991), GSSAPIHandler)
    print("Starting test server...")
    server.serve_forever()
    print("Test server shutdown.")
