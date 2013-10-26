from __future__ import absolute_import

import multiprocessing
import unittest

from gssapi import (
    Context, InitContext, AcceptContext, Credential, OID, C_ACCEPT
)


def server_worker(in_q, out_q):
    ctx = AcceptContext()
    while not ctx.established:
        out_q.put(ctx.step(in_q.get()))


def client_worker(in_q, out_q):
    default_accept_cred = Credential(usage=C_ACCEPT)
    ctx = InitContext(default_accept_cred.name)
    token = None
    while not ctx.established:
        out_q.put(ctx.step(token))
        token = in_q.get()


class AnyMechContextTest(unittest.TestCase):

    def test_default_context(self):
        queue1 = multiprocessing.Queue()
        queue2 = multiprocessing.Queue()
        client = multiprocessing.Process(target=client_worker, args=(queue1, queue2))
        server = multiprocessing.Process(target=server_worker, args=(queue2, queue1))
        client.start()
        server.start()
        client.join()
        server.join()


class KerberosContextTest(unittest.TestCase):

    def setUp(self):
        try:
            self.krb5mech = OID.mech_from_string('{1 2 840 113554 1 2 2}')
        except KeyError:
            self.skipTest("Kerberos 5 mech not available")
