from __future__ import absolute_import

import unittest

from mock import patch

from gssapi import get_all_mechs, OID, OIDSet, MutableOIDSet
from gssapi.oids import _release_OID_set
from gssapi.headers import ffi, C


class OIDTest(unittest.TestCase):

    def test_eq(self):
        allmechs = get_all_mechs()
        counter = 0
        for mech in allmechs:
            self.assertEqual(mech, mech)
            self.assertEqual(OID.mech_from_string(str(mech)), mech)
            self.assertEqual(
                sum(
                    1 if (OID.mech_from_string(str(mech)) == othermech) else 0
                    for othermech in allmechs
                ),
                1
            )
            if counter > 0:
                self.assertNotEqual(mech, allmechs[counter - 1])
            counter += 1

    def test_mech_from_string(self):
        self.assertRaises(ValueError, OID.mech_from_string, "not a real OID string")
        self.assertRaises(KeyError, OID.mech_from_string, "{1 1 1 1 1 1 1 1 1 1}")
        self.assertRaises(KeyError, OID.mech_from_string, "1.1.1.1.1.1.1.1.1.1")


class KerberosOIDTest(unittest.TestCase):

    OID_AS_STRING = '1.2.840.113554.1.2.2'

    def setUp(self):
        try:
            self.krb5mech = OID.mech_from_string(self.OID_AS_STRING)
        except KeyError:
            self.skipTest("Kerberos 5 mech not available")

    def test_mech_comparison(self):
        krb5mech2 = OID.mech_from_string(self.OID_AS_STRING)
        self.assertEqual(self.krb5mech, krb5mech2)
        self.assertEqual(hash(self.krb5mech), hash(krb5mech2))
        self.assertIn(self.krb5mech, get_all_mechs())
        self.assertNotEqual(self.krb5mech, "not a mech")

    def test_repr(self):
        self.assertIn(self.OID_AS_STRING, repr(self.krb5mech))

    def test_str(self):
        self.assertEqual(self.OID_AS_STRING, str(self.krb5mech))


class OIDSetTest(unittest.TestCase):

    def test_singleton_sets(self):
        allmechs = get_all_mechs()
        for mech in allmechs:
            self.check_singleton_set(mech, allmechs)

    def check_singleton_set(self, mech, allmechs):
        s = OIDSet.singleton_set(mech)
        self.assertIn(mech, s)
        for other in allmechs:
            if other != mech:
                self.assertNotIn(other, s)

    def test_in(self):
        for mech in get_all_mechs():
            self.assertIn(mech, get_all_mechs())
        self.assertNotIn(OID(ffi.new('gss_OID_desc[1]')[0]), get_all_mechs())
        self.assertNotIn("not an OID", get_all_mechs())

    def test_add(self):
        new_set = MutableOIDSet()
        prev_len = 0
        for mech in get_all_mechs():
            new_set.add(mech)
            self.assertEqual(len(new_set), prev_len + 1)
            prev_len += 1
        self.assertEqual(len(new_set), len(get_all_mechs()))
        for mech in get_all_mechs():
            self.assertIn(mech, new_set)
        self.assertRaises(TypeError, new_set.add, ('not a mech',))

    def test_init(self):
        self.assertRaises(TypeError, OIDSet, 'not a gss_OID_set')

    def test_length(self):
        self.assertEqual(len(OIDSet()), 0)
        new_set = OIDSet()
        new_set._oid_set = ffi.new('gss_OID_set[1]')
        self.assertEqual(len(new_set), 0)

    def test_array_access(self):
        all_mechs = get_all_mechs()
        for x in range(len(all_mechs)):
            assert all_mechs[x] in all_mechs
        self.assertRaises(IndexError, lambda n: all_mechs[n], -(len(all_mechs) + 1))
        self.assertRaises(IndexError, lambda n: all_mechs[n], len(all_mechs))

    def test_eq(self):
        self.assertEqual(get_all_mechs(), get_all_mechs())
        new_set1 = MutableOIDSet()
        new_set2 = MutableOIDSet()

        counter = 0
        for mech in get_all_mechs():
            new_set1.add(mech)
            self.assertEqual(new_set1, new_set1)
            counter += 1
            if counter < len(get_all_mechs()):
                self.assertNotEqual(new_set1, get_all_mechs())

        self.assertEqual(new_set1, get_all_mechs())

        counter = 0
        for mech in new_set1:
            new_set2.add(mech)
            self.assertEqual(new_set2, new_set2)
            counter += 1
            if counter < len(new_set1):
                self.assertNotEqual(new_set1, new_set2)

        self.assertEqual(new_set2, new_set1)
        self.assertEqual(new_set2, get_all_mechs())

    def test_ne(self):
        allmechs = get_all_mechs()
        if len(allmechs) < 2:
            self.skipTest("Only one available mechanism.")
        else:
            singleton_set1 = OIDSet.singleton_set(allmechs[0])
            singleton_set2 = OIDSet.singleton_set(allmechs[-1])
            self.assertNotEqual(singleton_set1, singleton_set2)

    def test_bad_types(self):
        allmechs = get_all_mechs()
        self.assertNotEqual(allmechs, 'a string')
        self.assertNotEqual(allmechs, 500)
        self.assertNotEqual(allmechs, ['spam'])
        self.assertNotEqual(allmechs, ['spam'] * len(allmechs))

    @patch('gssapi.oids.C.gss_create_empty_oid_set', wraps=C.gss_create_empty_oid_set)
    @patch('gssapi.oids.C.gss_indicate_mechs', wraps=C.gss_indicate_mechs)
    @patch('gssapi.oids.C.gss_release_oid_set', wraps=C.gss_release_oid_set)
    def test_matched_release(self, release, indicate, create):
        self.test_add()
        self.test_singleton_sets()
        self.test_in()
        self.test_array_access()
        self.test_eq()
        self.assertEqual(
            release.call_count,
            (create.call_count + indicate.call_count),
            "release count {0} != (create count {1} + indicate count {2})".format(
                release.call_count, create.call_count, indicate.call_count
            )
        )

    @patch('gssapi.oids.C.gss_release_oid_set', wraps=C.gss_release_oid_set)
    def test_release_all_mechs(self, mocked):
        allmechs = get_all_mechs()
        onemech = allmechs[0]
        del allmechs
        self.assertEqual(mocked.call_count, 0)
        del onemech
        self.assertEqual(mocked.call_count, 1)

    @patch('gssapi.oids.C.gss_release_oid_set', wraps=C.gss_release_oid_set)
    def test_destructor(self, mocked):
        new_set = OIDSet()
        del new_set
        self.assertEqual(mocked.call_count, 1)

    @patch('gssapi.oids.C.gss_release_oid_set', wraps=C.gss_release_oid_set)
    def test_doublefree(self, mocked):
        new_set = OIDSet()
        _release_OID_set(new_set._oid_set)
        _release_OID_set(new_set._oid_set)
        self.assertEqual(mocked.call_count, 1)
