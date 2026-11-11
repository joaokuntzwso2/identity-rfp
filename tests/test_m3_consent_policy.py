"""Pure policy regression tests; no live PostgreSQL or WSO2 required."""
import sys
import types
import unittest
from pathlib import Path

# The actual package is installed inside the Docker demo image. Stub only the DB
# import for policy-only tests on a Mac without the psycopg host dependency.
try:
    import psycopg
except ImportError:
    fake=types.ModuleType('psycopg')
    fake.rows=types.ModuleType('psycopg.rows')
    fake.rows.dict_row=object()
    sys.modules['psycopg']=fake
    sys.modules['psycopg.rows']=fake.rows

from demo.m3_consent import (verified_subject, permission_for_share,
                             correct_link_owner, correct_recipient)
from fastapi import HTTPException

class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.ana={'brand':'magalu','channel':'web','tenant':'magalu.demo',
                  'status':'authenticated','sub':'opaque-magalu-sub'}
        self.nets={'brand':'netshoes','channel':'web','tenant':'magalu.demo',
                   'status':'authenticated','sub':'opaque-netshoes-sub'}
        self.pay={'brand':'magalupay','channel':'web','tenant':'magalupay.demo',
                  'status':'authenticated','sub':'opaque-pay-sub'}
        self.link={'source_tenant':'magalu.demo','source_sub':'opaque-magalu-sub',
                   'recipient_tenant':'magalu.demo','recipient_sub':'opaque-netshoes-sub'}
    def test_valid_brand_session(self):
        self.assertEqual(verified_subject([self.ana],'magalu'),('magalu.demo','opaque-magalu-sub'))
    def test_wrong_root_is_not_trusted(self):
        with self.assertRaises(HTTPException):
            verified_subject([{**self.ana,'tenant':'magalupay.demo'}],'magalu')
    def test_missing_login_rejected(self):
        with self.assertRaises(HTTPException): verified_subject([],'magalu')
    def test_conflicting_channel_users_rejected(self):
        with self.assertRaises(HTTPException):
            verified_subject([self.ana,{**self.ana,'channel':'app','sub':'other'}],'magalu')
    def test_source_is_only_consent_owner(self):
        self.assertTrue(correct_link_owner(self.link,'magalu.demo','opaque-magalu-sub'))
        self.assertFalse(correct_link_owner(self.link,'magalu.demo','opaque-netshoes-sub'))
    def test_no_grant_is_denied(self):
        self.assertEqual(permission_for_share(self.link,None,'magalu.demo','opaque-netshoes-sub'),
                         (False,'CONSENT_NOT_GRANTED_OR_REVOKED'))
    def test_revocation_is_immediately_denied(self):
        self.assertFalse(permission_for_share(self.link,'REVOKED','magalu.demo','opaque-netshoes-sub')[0])
    def test_active_grant_is_allowed_only_to_target(self):
        self.assertTrue(permission_for_share(self.link,'GRANTED','magalu.demo','opaque-netshoes-sub')[0])
        self.assertFalse(permission_for_share(self.link,'GRANTED','magalupay.demo','opaque-netshoes-sub')[0])
        self.assertFalse(permission_for_share(self.link,'GRANTED','magalu.demo','other-user')[0])
    def test_direction_is_not_reversible(self):
        self.assertFalse(correct_link_owner(self.link,'magalu.demo','opaque-netshoes-sub'))
        self.assertFalse(correct_recipient(self.link,'magalu.demo','opaque-magalu-sub'))

if __name__=='__main__':unittest.main()
