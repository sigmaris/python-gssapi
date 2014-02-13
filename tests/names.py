from __future__ import absolute_import

import unittest
import re
import os
import pwd
import platform
import socket

from ctypes import byref
from mock import patch

from gssapi import (
    GSSException, Name, OID, C_NT_USER_NAME, C_NT_MACHINE_UID_NAME, C_NT_STRING_UID_NAME,
    C_NT_HOSTBASED_SERVICE
)
from gssapi.headers import gssapi_h


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
        Name(self.user, C_NT_USER_NAME)
        Name("host@example.com", C_NT_HOSTBASED_SERVICE)
        Name("HTTP", C_NT_HOSTBASED_SERVICE)
        if not self.is_heimdal_mac:
            Name(str(self.uid), C_NT_STRING_UID_NAME)
            Name(self.uid, C_NT_MACHINE_UID_NAME)

    def test_display_name(self):
        self.assertEqual("spam", str(Name("spam")))
        self.assertEqual(self.user, str(Name(self.user, C_NT_USER_NAME)))
        self.assertEqual("host@example.com", str(Name("host@example.com", C_NT_HOSTBASED_SERVICE)))
        self.assertEqual("HTTP", str(Name("HTTP", C_NT_HOSTBASED_SERVICE)))
        if not self.is_heimdal_mac:
            self.assertEqual(str(self.uid), str(Name(str(self.uid), C_NT_STRING_UID_NAME)))

    def test_bad_canonicalize(self):
        host_name = Name("host@example.com", C_NT_HOSTBASED_SERVICE)
        self.assertRaises(TypeError, host_name.canonicalize, ("not an OID"))

    def test_bad_input(self):
        self.assertRaises(TypeError, Name, (['list', 'of', 'things']))


class KerberosNameTest(NameTest):

    def setUp(self):
        super(KerberosNameTest, self).setUp()
        try:
            self.krb5mech = OID.mech_from_string('{1 2 840 113554 1 2 2}')
        except KeyError:
            self.skipTest("Kerberos 5 mech not available")

    def test_canonicalize(self):
        self.assertRegexpMatches(
            str(Name("spam").canonicalize(self.krb5mech)),
            'spam@.+'
        )
        self.assertRegexpMatches(
            str(Name(self.user, C_NT_USER_NAME).canonicalize(self.krb5mech)),
            re.escape(self.user) + '@.+'
        )
        self.assertRegexpMatches(
            str(Name("host@{0}".format(self.fqdn), C_NT_HOSTBASED_SERVICE).canonicalize(self.krb5mech)),
            'host/' + re.escape(self.fqdn) + '@.+'
        )
        if not self.is_heimdal_mac:
            self.assertRegexpMatches(
                str(Name(str(self.uid), C_NT_STRING_UID_NAME).canonicalize(self.krb5mech)),
                '.+@.+'
            )
            self.assertRegexpMatches(
                str(Name(self.uid, C_NT_MACHINE_UID_NAME).canonicalize(self.krb5mech)),
                '.+@.+'
            )
        self.assertRaises(
            GSSException,
            Name("spam").canonicalize(self.krb5mech).canonicalize,
            (self.krb5mech,)
        )

    def test_eq(self):
        name1 = Name(self.user, C_NT_USER_NAME)
        name2 = Name(self.user, C_NT_USER_NAME)
        self.assertEqual(name1, name2)
        name3 = Name("host@example.com", C_NT_HOSTBASED_SERVICE)
        self.assertNotEqual(name1, name3)
        self.assertNotEqual("not a real name", name1)
        self.assertFalse(name1 == 10101)

    def test_compare_canonicalized(self):
        name1 = Name(self.user, C_NT_USER_NAME)
        canon1 = name1.canonicalize(self.krb5mech)
        self.assertEqual(name1, canon1)
        name2 = Name("notarealusername", C_NT_USER_NAME)
        canon2 = name2.canonicalize(self.krb5mech)
        self.assertEqual(name2, canon2)
        self.assertNotEqual(canon1, canon2)

    def test_export(self):
        name1exp = Name("spam").canonicalize(self.krb5mech).export()
        self.assertIsInstance(name1exp, bytes)
        self.assertGreater(len(name1exp), 0)

        user_name_exp = Name(self.user, C_NT_USER_NAME).canonicalize(self.krb5mech).export()
        self.assertIsInstance(user_name_exp, bytes)
        self.assertGreater(len(user_name_exp), 0)

        svc_name_exp = Name("host@example.com", C_NT_HOSTBASED_SERVICE).canonicalize(self.krb5mech).export()
        self.assertIsInstance(svc_name_exp, bytes)
        self.assertGreater(len(svc_name_exp), 0)

        bare_svc_name_exp = Name("HTTP", C_NT_HOSTBASED_SERVICE).canonicalize(self.krb5mech).export()
        self.assertIsInstance(bare_svc_name_exp, bytes)
        self.assertGreater(len(bare_svc_name_exp), 0)
        if not self.is_heimdal_mac:
            str_uid_name_exp = Name(str(self.uid), C_NT_STRING_UID_NAME).canonicalize(self.krb5mech).export()
            self.assertIsInstance(str_uid_name_exp, bytes)
            self.assertGreater(len(str_uid_name_exp), 0)

            machine_uid_name_exp = Name(self.uid, C_NT_MACHINE_UID_NAME).canonicalize(self.krb5mech).export()
            self.assertIsInstance(machine_uid_name_exp, bytes)
            self.assertGreater(len(machine_uid_name_exp), 0)

    @patch('gssapi.names.gss_import_name', wraps=gssapi_h.gss_import_name)
    @patch('gssapi.names.gss_canonicalize_name', wraps=gssapi_h.gss_canonicalize_name)
    @patch('gssapi.names.gss_release_name', wraps=gssapi_h.gss_release_name)
    def test_matched_release(self, release, canonicalize, imprt):
        self.test_import_name()
        self.test_display_name()
        self.test_canonicalize()
        self.test_eq()
        self.test_compare_canonicalized()
        self.assertEqual(release.call_count, (imprt.call_count + canonicalize.call_count))

    @patch('gssapi.names.gss_release_name', wraps=gssapi_h.gss_release_name)
    def test_doublefree(self, mocked):
        name = Name("spam", C_NT_USER_NAME)
        backing_struct = name._name
        name._release()
        name._release()
        del name
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(repr(mocked.call_args[0][1]), repr(byref(backing_struct)))
