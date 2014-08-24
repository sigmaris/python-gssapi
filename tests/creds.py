from __future__ import absolute_import

import platform
import unittest

from gssapi import (
    bindings,
    Credential, NoCredential, CredentialsExpired, GSSException, GSSCException,
    S_NO_CRED, C_INITIATE, C_ACCEPT
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
        except (NoCredential, CredentialsExpired):
            self.skipTest("No default init credential available, try running with a Kerberos ticket.")
        self.is_heimdal_mac = False
        if platform.system() == 'Darwin':
            mac_ver = platform.mac_ver()[0].split('.')
            if int(mac_ver[0]) >= 10 and int(mac_ver[1]) >= 7:
                self.is_heimdal_mac = True


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

    def test_export(self):
        if self.is_heimdal_mac:
            self.skipTest("gss_export_cred is bugged on Mac OS X 10.7+")
        if not hasattr(bindings.C, 'gss_export_cred'):
            self.skipTest("No support for gss_export_cred")
        else:
            self.assertGreater(len(str(self.cred.export())), 0)

    def test_export_import(self):
        if self.is_heimdal_mac:
            self.skipTest("gss_export_cred is bugged on Mac OS X 10.7+")
        if not hasattr(bindings.C, 'gss_export_cred'):
            self.skipTest("No support for gss_export_cred")
        else:
            orig_name = self.cred.name
            exported_token = self.cred.export()
            imported_cred = Credential.imprt(exported_token)
            self.assertEqual(orig_name, imported_cred.name)

    def test_export_import_raises(self):
        if self.is_heimdal_mac:
            self.skipTest("gss_export_cred is bugged on Mac OS X 10.7+")
        if not hasattr(bindings.C, 'gss_export_cred'):
            self.skipTest("No support for gss_export_cred")
        else:
            exported_token = self.cred.export()
            with self.assertRaises(GSSException):
                # Cutting off characters should make token invalid
                Credential.imprt(exported_token[4:])

class DefaultAcceptCredentialTest(DefaultInitCredentialTest):

    def setUp(self):
        try:
            self.cred = Credential(usage=C_ACCEPT)
            self.cred.name
        except GSSCException as exc:
            if (
                exc.maj_status == S_NO_CRED or 'Permission denied' in exc.message
                or 'keytab is nonexistent or empty' in exc.message
            ):
                self.skipTest("No default accept credential available, "
                    "try running with a Kerberos keytab readable.")
            else:
                raise
        self.is_heimdal_mac = False
        if platform.system() == 'Darwin':
            mac_ver = platform.mac_ver()[0].split('.')
            if int(mac_ver[0]) >= 10 and int(mac_ver[1]) >= 7:
                self.is_heimdal_mac = True

    def test_usage(self):
        self.assertEqual(C_ACCEPT, self.cred.usage)
