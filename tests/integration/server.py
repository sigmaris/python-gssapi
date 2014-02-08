import SocketServer

from gssapi import AcceptContext


class GSSAPIHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        global server
        print("{0} connected".format(self.client_address[0]))
        ctx = AcceptContext()
        sockfile = self.request.makefile('rwb')
        while not ctx.established:
            print("{0} handshaking...".format(self.client_address[0]))
            in_token = sockfile.readline().decode('base64')
            print("{0} sent {1} bytes.").format(self.client_address[0])
            sockfile.write(ctx.step().encode('base64'))
        print("{0} handshake complete.".format(self.client_address[0]))
        sockfile.write("+OK\n")
        client_command = sockfile.readline().strip()
        print("{0} command: {1}".format(self.client_address[0], client_command))
        if client_command == '+SHUTDOWN':
            server.shutdown()


if __name__ == '__main__':
    server = SocketServer.ThreadingTCPServer(('', 59991), GSSAPIHandler)
    print("Starting test server...")
    server.serve_forever()
    print("Test server shutdown.")
