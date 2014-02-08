from __future__ import absolute_import

import unittest

from gssapi import (
    Credential, GSSCException,
    S_NO_CRED, S_CREDENTIALS_EXPIRED, C_INITIATE, C_ACCEPT
)


class CredentialTest(unittest.TestCase):

    def test_bad_args(self):
        self.assertRaises(TypeError, Credential, desired_name='incorrect type')
        self.assertRaises(TypeError, Credential, desired_mechs='incorrect type')
        self.assertRaises(TypeError, Credential, lifetime='incorrect type')
        self.assertRaises(TypeError, Credential, usage='incorrect type')


class DefaultInitCredentialTest(unittest.TestCase):

    def setUp(self):
        try:
            self.cred = Credential(usage=C_INITIATE)
            self.cred.name
        except GSSCException as exc:
            if exc.maj_status in (S_NO_CRED, S_CREDENTIALS_EXPIRED):
                self.skipTest("No default init credential available, try running with a Kerberos ticket.")
            else:
                raise

    def test_lifetime(self):
        first_lifetime = self.cred.lifetime
        self.assertGreaterEqual(first_lifetime, 0)
        second_lifetime = self.cred.lifetime
        self.assertGreaterEqual(second_lifetime, 0)
        self.assertLessEqual(second_lifetime, first_lifetime)

    def test_usage(self):
        self.assertEqual(C_INITIATE, self.cred.usage)

    def test_name(self):
        self.assertGreater(len(str(self.cred.name)), 0)


class DefaultAcceptCredentialTest(DefaultInitCredentialTest):

    def setUp(self):
        try:
            self.cred = Credential(usage=C_ACCEPT)
            self.cred.name
        except GSSCException as exc:
            if exc.maj_status == S_NO_CRED or 'Permission denied' in exc.message:
                self.skipTest("No default accept credential available, "
                    "try running with a Kerberos keytab readable.")
            else:
                raise

    def test_usage(self):
        self.assertEqual(C_ACCEPT, self.cred.usage)
