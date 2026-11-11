"""Offline safety and packaging tests for M3 launchers."""
import subprocess
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
class M3LauncherTests(unittest.TestCase):
    def test_module_style_provisioning(self):
        sh=(ROOT/'scripts/provision-m3-oauth-test.sh').read_text()
        self.assertIn('python -m scripts.m3_provision_oauth_test_client',sh)
        self.assertNotIn('python scripts/m3_provision_oauth_test_client.py',sh)
    def test_isolated_python_dependencies(self):
        sh=(ROOT/'scripts/m3-local.sh').read_text()
        for item in ('PyJWT[crypto]==2.10.1','requests==2.32.3','cryptography==44.0.2'):
            self.assertIn(item,sh)
        self.assertIn('python3 -m venv',sh)
        self.assertIn('generated/m3-tokens/subject.jwt',sh)
        self.assertIn('generated/m3-tokens/actor.jwt',sh)
    def test_shell_syntax(self):
        for script in (ROOT/'scripts').glob('*.sh'):
            subprocess.run(['bash','-n',str(script)],check=True)
if __name__=='__main__': unittest.main()
