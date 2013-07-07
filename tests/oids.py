from __future__ import absolute_import

import unittest
from ctypes import byref

from mock import patch

from gssapi import get_all_mechs, OID, OIDSet, gssapi_h


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

    def test_mech_comparison(self):
        try:
            krb5mech1 = OID.mech_from_string('{1 2 840 113554 1 2 2}')
        except KeyError:
            self.skipTest("Kerberos 5 mech not available")
        krb5mech2 = OID.mech_from_string('1.2.840.113554.1.2.2')
        self.assertEqual(krb5mech1, krb5mech2)
        self.assertEqual(hash(krb5mech1), hash(krb5mech2))
        self.assertIn(krb5mech1, get_all_mechs())


class OIDSetTest(unittest.TestCase):

    def test_singleton_sets(self):
        allmechs = get_all_mechs()
        for mech in allmechs:
            yield self.check_singleton_set(mech, allmechs)

    def check_singleton_set(self, mech, allmechs):
        s = OIDSet.singleton_set(mech)
        self.assertIn(mech, s)
        for other in allmechs:
            self.assertNotIn(other, s)

    def test_in(self):
        for mech in get_all_mechs():
            self.assertIn(mech, get_all_mechs())
        self.assertNotIn(OID(gssapi_h.gss_OID_desc()), get_all_mechs())
        self.assertNotIn("not an OID", get_all_mechs())

    def test_add(self):
        new_set = OIDSet()
        prev_len = 0
        for mech in get_all_mechs():
            new_set.add(mech)
            self.assertEqual(len(new_set), prev_len + 1)
            prev_len += 1
        self.assertEqual(len(new_set), len(get_all_mechs()))
        for mech in get_all_mechs():
            self.assertIn(mech, new_set)

    def test_init(self):
        self.assertRaises(TypeError, OIDSet, 'not a gss_OID_set')

    def test_length(self):
        self.assertEqual(len(OIDSet()), 0)
        new_set = OIDSet()
        new_set._oid_set = gssapi_h.gss_OID_set()
        self.assertEqual(len(new_set), 0)

    def test_array_access(self):
        all_mechs = get_all_mechs()
        for x in xrange(len(all_mechs)):
            assert all_mechs[x] in all_mechs
        self.assertRaises(IndexError, lambda n: all_mechs[n], -1)
        self.assertRaises(IndexError, lambda n: all_mechs[n], len(all_mechs))

    def test_eq(self):
        self.assertEqual(get_all_mechs(), get_all_mechs())
        new_set1 = OIDSet()
        new_set2 = OIDSet()

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

    @patch('gssapi.oids.gss_create_empty_oid_set', wraps=gssapi_h.gss_create_empty_oid_set)
    @patch('gssapi.oids.gss_indicate_mechs', wraps=gssapi_h.gss_indicate_mechs)
    @patch('gssapi.oids.gss_release_oid_set', wraps=gssapi_h.gss_release_oid_set)
    def test_matched_release(self, release, indicate, create):
        self.test_add()
        self.test_singleton_sets()
        self.test_in()
        self.test_array_access()
        self.test_eq()
        self.assertEqual(release.call_count, (indicate.call_count + create.call_count))

    @patch('gssapi.oids.gss_release_oid_set', wraps=gssapi_h.gss_release_oid_set)
    def test_release_all_mechs(self, mocked):
        allmechs = get_all_mechs()
        backing_set = allmechs._oid_set
        onemech = allmechs[0]
        del allmechs
        self.assertEqual(mocked.call_count, 0)
        del onemech
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(repr(mocked.call_args[0][1]), repr(byref(backing_set)))

    @patch('gssapi.oids.gss_release_oid_set', wraps=gssapi_h.gss_release_oid_set)
    def test_destructor(self, mocked):
        new_set = OIDSet()
        backing_set = new_set._oid_set
        del new_set
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(repr(mocked.call_args[0][1]), repr(byref(backing_set)))

    @patch('gssapi.oids.gss_release_oid_set', wraps=gssapi_h.gss_release_oid_set)
    def test_doublefree(self, mocked):
        new_set = OIDSet()
        backing_set = new_set._oid_set
        new_set._release()
        new_set._release()
        del new_set
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(repr(mocked.call_args[0][1]), repr(byref(backing_set)))
