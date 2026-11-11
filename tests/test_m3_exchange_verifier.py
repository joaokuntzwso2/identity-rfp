import unittest
import importlib.util
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'scripts'/'m3_token_exchange_verify.py'
spec=importlib.util.spec_from_file_location('exchange_verify',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ExchangeTest(unittest.TestCase):
    def test_string_scope(self): self.assertEqual(m.token_scopes({'scope':'requests:read requests:create'}),{'requests:read','requests:create'})
    def test_array_scope(self): self.assertEqual(m.token_scopes({'scope':['openid','requests:read']}),{'openid','requests:read'})
    def test_unknown_scope_format_fails_closed(self): self.assertEqual(m.token_scopes({'scope':{'bad':'thing'}}),set())
    def test_grant_names(self): self.assertEqual(m.EXCHANGE,'urn:ietf:params:oauth:grant-type:token-exchange')
if __name__=='__main__':unittest.main()
