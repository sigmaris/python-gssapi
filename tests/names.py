from __future__ import absolute_import

import unittest
import re
import os
import pwd
import platform
import socket

from gssapi import (
    Name, OID, GSS_C_NT_USER_NAME, GSS_C_NT_MACHINE_UID_NAME, GSS_C_NT_STRING_UID_NAME,
    GSS_C_NT_HOSTBASED_SERVICE
)


class NameTest(unittest.TestCase):

    def setUp(self):
        self.fqdn = socket.getfqdn()
        self.uid = os.getuid()
        self.user = pwd.getpwuid(self.uid).pw_name
        self.is_heimdal_mac = False
        if platform.system() == 'Darwin':
            mac_ver = platform.mac_ver()[0].split('.')
            if int(mac_ver[0]) >= 10 and int(mac_ver[1]) >= 7:
                self.is_heimdal_mac = True

    def test_import_name(self):
        Name("spam")
        Name(self.user, GSS_C_NT_USER_NAME)
        Name("host@example.com", GSS_C_NT_HOSTBASED_SERVICE)
        Name("HTTP", GSS_C_NT_HOSTBASED_SERVICE)
        if not self.is_heimdal_mac:
            Name(str(self.uid), GSS_C_NT_STRING_UID_NAME)
            Name(self.uid, GSS_C_NT_MACHINE_UID_NAME)

    def test_display_name(self):
        self.assertEquals("spam", str(Name("spam")))
        self.assertEquals(self.user, str(Name(self.user, GSS_C_NT_USER_NAME)))
        self.assertEquals("host@example.com", str(Name("host@example.com", GSS_C_NT_HOSTBASED_SERVICE)))
        self.assertEquals("HTTP", str(Name("HTTP", GSS_C_NT_HOSTBASED_SERVICE)))
        if not self.is_heimdal_mac:
            self.assertEquals(str(self.uid), str(Name(str(self.uid), GSS_C_NT_STRING_UID_NAME)))

    def test_canonicalize(self):
        try:
            krb5mech = OID.mech_from_string('{1 2 840 113554 1 2 2}')
        except KeyError:
            self.skipTest("Kerberos 5 mech not available")
        self.assertRegexpMatches(
            str(Name("spam").canonicalize(krb5mech)),
            'spam@.+'
        )
        self.assertRegexpMatches(
            str(Name(self.user, GSS_C_NT_USER_NAME).canonicalize(krb5mech)),
            re.escape(self.user) + '@.+'
        )
        self.assertRegexpMatches(
            str(Name("host@{0}".format(self.fqdn), GSS_C_NT_HOSTBASED_SERVICE).canonicalize(krb5mech)),
            'host/' + re.escape(self.fqdn) + '@.+'
        )
        if not self.is_heimdal_mac:
            self.assertRegexpMatches(
                str(Name(str(self.uid), GSS_C_NT_STRING_UID_NAME).canonicalize(krb5mech)),
                '.+@.+'
            )
            self.assertRegexpMatches(
                str(Name(self.uid, GSS_C_NT_MACHINE_UID_NAME).canonicalize(krb5mech)),
                '.+@.+'
            )

    def test_export(self):
        try:
            krb5mech = OID.mech_from_string('{1 2 840 113554 1 2 2}')
        except KeyError:
            self.skipTest("Kerberos 5 mech not available")
        name1exp = Name("spam").canonicalize(krb5mech).export()
        self.assertIsInstance(name1exp, str)
        self.assertGreater(len(name1exp), 0)

        user_name_exp = Name(self.user, GSS_C_NT_USER_NAME).canonicalize(krb5mech).export()
        self.assertIsInstance(user_name_exp, str)
        self.assertGreater(len(user_name_exp), 0)

        svc_name_exp = Name("host@example.com", GSS_C_NT_HOSTBASED_SERVICE).canonicalize(krb5mech).export()
        self.assertIsInstance(svc_name_exp, str)
        self.assertGreater(len(svc_name_exp), 0)

        bare_svc_name_exp = Name("HTTP", GSS_C_NT_HOSTBASED_SERVICE).canonicalize(krb5mech).export()
        self.assertIsInstance(bare_svc_name_exp, str)
        self.assertGreater(len(bare_svc_name_exp), 0)
        if not self.is_heimdal_mac:
            str_uid_name_exp = Name(str(self.uid), GSS_C_NT_STRING_UID_NAME).canonicalize(krb5mech).export()
            self.assertIsInstance(str_uid_name_exp, str)
            self.assertGreater(len(str_uid_name_exp), 0)

            machine_uid_name_exp = Name(self.uid, GSS_C_NT_MACHINE_UID_NAME).canonicalize(krb5mech).export()
            self.assertIsInstance(machine_uid_name_exp, str)
            self.assertGreater(len(machine_uid_name_exp), 0)
