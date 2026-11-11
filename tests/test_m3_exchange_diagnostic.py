import importlib.util
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
# Original verifier is available beside the diagnostic after installation.
try:
    import m3_exchange_diagnose as d
except ModuleNotFoundError:
    d=None

@unittest.skipIf(d is None,'Diagnostic dependencies not installed')
class Diagnostics(unittest.TestCase):
    def test_error_redaction(self):
        secret='eyJabcdefghijklmno.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.abcd'
        x=d.sanitize_description('bad subject_token='+secret+' more')
        self.assertNotIn(secret,x)
    def test_oauth_code_allowlist(self):
        self.assertEqual(d.oauth_error({'error':'invalid_scope','error_description':'Scope denied'})['error'],'invalid_scope')
        self.assertEqual(d.oauth_error({'error':'bad '+('x'*200)})['error'],'error_code_unavailable')
    def test_error_token_never_in_output(self):
        self.assertNotIn('access_token',d.oauth_error({'error':'invalid_grant','access_token':'sensitive'}))
    def test_non_json(self):
        self.assertEqual(d.oauth_error('oops')['error'],'non_json_response')
if __name__=='__main__':unittest.main()
