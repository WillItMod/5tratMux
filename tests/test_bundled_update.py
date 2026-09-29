"""Verify offline signed installation and rejection before container mutation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / '5tratmux-update'

@unittest.skipUnless(sys.platform.startswith('linux'), 'updater targets Linux/GNU coreutils')
class BundledUpdateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        self.library = self.root / 'functions.sh'
        self.library.write_text(SOURCE.read_text().split('case "${1:---check}" in')[0])
        self.env = dict(os.environ, MUX_CONTAINER_NAME='bundle-test',
                        MUX_UPDATER_ENV_FILE=str(self.root/'absent.env'),
                        MUX_RUNTIME_DIR=str(self.root), MUX_STATUS_FILE=str(self.root/'status.json'),
                        MUX_DNS_CONFIG_FILE=str(self.root/'absent.json'),
                        TEST_BUNDLE=str(self.bundle), TEST_ROOT=str(self.root))
        self.key = self.root/'key.pem'
        self.pub = self.root/'pub.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.key)], check=True, capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(self.key),'-pubout','-out',str(self.pub)], check=True, capture_output=True)
        self.archive = self.bundle/'5tratmux-0.9.59-amd64.oci.tar.gz'
        self.archive.write_bytes(b'test OCI bytes')
        self.manifest = {'version':'0.9.59','channel':'MAIN','images':{'amd64':{
            'image':'test:0.9.59','url':'https://unreachable.invalid/archive',
            'sha256':hashlib.sha256(self.archive.read_bytes()).hexdigest()}}}
        self.sign()

    def sign(self):
        path = self.bundle/'5tratmux-release.json'
        path.write_text(json.dumps(self.manifest))
        subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(self.key),'-rawin','-in',str(path),
                        '-out',str(self.bundle/'5tratmux-release.json.sig')],check=True,capture_output=True)

    def run_install(self, health=True, installed='0.9.58'):
        code = '''source "$1"
require_root() { :; }; require_commands() { :; }; ensure_config() { :; }
write_public_key() { PUBLIC_KEY_FILE="$TEST_ROOT/pub.pem"; }
architecture() { echo amd64; }
installed_version() { echo '''+installed+'''; }
docker() { printf '%s\\n' "$*" >> "$TEST_ROOT/docker.log"; }
curl() { printf '%s\\n' "$*" >> "$TEST_ROOT/network.log"; return 99; }
wait_for_health() { '''+('return 0' if health else 'return 1')+'''; }
start_container() { printf '%s\\n' "$*" >> "$TEST_ROOT/started.log"; }
install() { :; }; enable_watchdog_service() { :; }; power_desired_on() { return 0; }
install_release "$TEST_BUNDLE"
'''
        return subprocess.run(['bash','-c',code,'test',str(self.library)],env=self.env,text=True,capture_output=True)

    def assert_untouched(self, result):
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'docker.log').exists())
        self.assertFalse((self.root/'network.log').exists())

    def test_install_uses_only_signed_local_archive(self):
        result=self.run_install()
        self.assertEqual(result.returncode,0,result.stderr)
        log=(self.root/'docker.log').read_text()
        self.assertIn('load --input '+str(self.archive),log)
        self.assertIn('stop bundle-test',log)
        self.assertFalse((self.root/'network.log').exists())
        self.assertEqual((self.root/'installed-version').read_text().strip(),'0.9.59')

    def test_tampered_manifest_is_rejected(self):
        (self.bundle/'5tratmux-release.json').write_text('{"version":"9.9.9"}')
        self.assert_untouched(self.run_install())

    def test_tampered_archive_is_rejected(self):
        self.archive.write_bytes(b'bad image')
        self.assert_untouched(self.run_install())

    def test_missing_archive_never_falls_back_to_download(self):
        self.archive.unlink()
        self.assert_untouched(self.run_install())

    def test_path_version_is_rejected(self):
        self.manifest['version']='../../outside'
        self.sign()
        self.assert_untouched(self.run_install())

    def test_symlink_archive_is_rejected(self):
        other=self.root/'outside'
        self.archive.rename(other)
        self.archive.symlink_to(other)
        self.assert_untouched(self.run_install())

    def test_failed_health_restores_previous_container(self):
        result=self.run_install(health=False)
        self.assertNotEqual(result.returncode,0)
        log=(self.root/'docker.log').read_text()
        self.assertIn('container rm --force bundle-test',log)
        self.assertIn('start bundle-test',log)
        self.assertIn('previous release was restored',result.stderr)
        self.assertFalse((self.root/'network.log').exists())

    def test_newer_installed_version_is_preserved(self):
        result=self.run_install(installed='0.9.60')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.root/'docker.log').exists())
        self.assertFalse((self.root/'network.log').exists())

if __name__=='__main__': unittest.main()
