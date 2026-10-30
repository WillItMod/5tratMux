"""Verify packaged browser assets before a signed runtime replaces the old one."""
import json
import os
from pathlib import Path
import sys
import unittest

import test_updater_hardening as fixtures


class WebAssetVerificationTests(unittest.TestCase):
    publish = fixtures.UpdaterHardeningTests.publish
    run_shell = fixtures.UpdaterHardeningTests.run_shell
    install = fixtures.UpdaterHardeningTests.install

    def setUp(self):
        fixtures.UpdaterHardeningTests.setUp(self)
        self.publish('0.9.88')
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.index = self.assets / 'index.html'
        self.index.write_text('<!doctype html><html><head>'
                              '<link rel="stylesheet" href="app.css?v=114">'
                              '<script src="app.js?v=127" defer></script>'
                              '<script type="module" src="network-dns.mjs?v=3"></script>'
                              '</head><body></body></html>')
        (self.assets / 'app.css').write_text('body { color: white; }')
        (self.assets / 'app.js').write_text('window.loaded = true;')
        (self.assets / 'network-dns.mjs').write_text('export const ready = true;')
        (self.root / 'data').mkdir()
        self.saved = self.root / 'data' / 'settings.json'
        self.saved.write_text('{"wallet":"fixture","routes":["saved"],"licence":"retained"}')
        self.saved_bytes = self.saved.read_bytes()

        # The candidate verifier calls an actual bounded subprocess, while the
        # existing runtime lifecycle fixture still invokes the same Docker model.
        source = fixtures.DOCKER.replace('import hashlib, json, os, sys',
                                          'import hashlib, json, os, sys, tarfile')
        source = source.replace("elif a[0]=='update':", '''elif a[0]=='cp':
 if state.get('failWebCopy'): fail()
 identity, source = a[1].split(':',1)
 assert identity in containers and containers[identity].get('WebCheck')
 assert source.startswith('/app/static/')
 assert a[2] == '-'
 if state.get('oversizedWebHeader'):
  header=tarfile.TarInfo(Path(source).name)
  header.size=state['oversizedWebHeader']
  sys.stdout.buffer.write(header.tobuf())
 else:
  with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
   archive.add(r/'assets'/source[len('/app/static/'):], arcname=Path(source).name, recursive=False)
 if state.get('failWebCopyAfterData'): fail()
elif a[0]=='create' and '--entrypoint' in a and a[a.index('--entrypoint')+1]=='/bin/true':
 identity=a[a.index('--name')+1]
 assert identity.startswith('5tratmux-web-check-')
 assert '--network' in a and a[a.index('--network')+1]=='none'
 assert '--read-only' in a and '--mount' not in a and '--env-file' not in a
 assert a[a.index('--entrypoint')+1]=='/bin/true'
 containers[identity]={'Id':'e'*64,'State':{'Running':False},'Image':a[-1], 'WebCheck':True}
 if state.get('loseWebCreateResponse'): fail()
 print('e'*64)
elif a[0]=='update':''')
        (self.root / 'docker.py').write_text(source)
        binary = self.root / 'bin'
        binary.mkdir()
        docker = binary / 'docker'
        docker.write_text(f'#!{sys.executable}\n' + source)
        docker.chmod(0o755)
        self.env['PATH'] = str(binary) + os.pathsep + self.env['PATH']

    def assert_saved(self):
        self.assertEqual(self.saved.read_bytes(), self.saved_bytes)
        self.assertFalse(any(c.get('WebCheck') for c in self.state['containers'].values()))

    def assert_candidate_failure_preserves_runtime(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.status['phase'], 'failed')
        self.assertEqual(self.state['containers']['test-mux']['Image'], fixtures.OLD)
        self.assertFalse(any(a[0] in ('stop', 'rename', 'run', 'start', 'restart') for a in self.calls))
        self.assert_saved()

    def test_verified_candidate_installs_and_removes_stopped_inspection_container(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.status['phase'], 'healthy')
        self.assertEqual(self.state['containers']['test-mux']['Image'], fixtures.NEW)
        self.assertTrue(any(a[0]=='cp' for a in self.calls))
        self.assertFalse(any(a[0]=='start' and a[-1].startswith('5tratmux-web-check-') for a in self.calls))
        self.assert_saved()

    def test_saved_off_installs_without_starting_mux_or_health_checks(self):
        (self.root / 'power.json').write_text('{"desired":"off"}')
        self.state['containers']['test-mux']['State'].update(Running=False, Status='exited')
        self.state['containers']['test-mux']['HostConfig']['RestartPolicy']['Name'] = 'no'
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.status['phase'], 'powered_off')
        current = self.state['containers']['test-mux']
        self.assertFalse(current['State']['Running'])
        self.assertEqual(current['HostConfig']['RestartPolicy']['Name'], 'no')
        self.assertFalse((self.root / 'health').exists())
        self.assertFalse(any(a[0] in ('run', 'start', 'restart') for a in self.calls))
        self.assert_saved()

    def test_root_relative_assets_are_rejected_before_existing_mux_is_stopped(self):
        self.index.write_text(self.index.read_text().replace('href="app.css', 'href="/app.css'))
        self.assert_candidate_failure_preserves_runtime(self.install())

    def test_missing_asset_is_rejected_and_helper_is_cleaned_up(self):
        (self.assets / 'network-dns.mjs').unlink()
        self.assert_candidate_failure_preserves_runtime(self.install())

    def test_html_in_script_is_rejected_before_runtime_replacement(self):
        (self.assets / 'app.js').write_text('<!doctype html><html>Login</html>')
        self.assert_candidate_failure_preserves_runtime(self.install())

    def test_copy_failure_preserves_runtime_and_cleans_up_helper(self):
        for failure in ('failWebCopy', 'failWebCopyAfterData'):
            with self.subTest(failure=failure):
                self.state[failure] = True
                self.assert_candidate_failure_preserves_runtime(self.install())
                self.state[failure] = False

    def test_lost_create_response_still_removes_named_stopped_helper(self):
        self.state['loseWebCreateResponse'] = True
        self.assert_candidate_failure_preserves_runtime(self.install())
        created = next(a for a in self.calls if a[0] == 'create')
        name = created[created.index('--name') + 1]
        self.assertTrue(any(a[:2] == ['container', 'rm'] and a[-1] == name for a in self.calls))

    def test_stream_header_limits_reject_before_opening_destination(self):
        self.state['containers']['fixture-web'] = {'WebCheck': True}
        for declared, limit, budget in ((9 * 1024 * 1024, 8 * 1024 * 1024, 32 * 1024 * 1024),
                                        (1024, 8 * 1024 * 1024, 512)):
            with self.subTest(declared=declared, budget=budget):
                self.state['oversizedWebHeader'] = declared
                result = self.run_shell('web_check_copy fixture-web /app/static/app.js '
                                        f'"$TEST_ROOT/bounded.js" {limit} {budget}')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('oversized', result.stderr)
                self.assertFalse((self.root / 'bounded.js').exists())

    def test_backend_health_failure_still_restores_previous_runtime(self):
        result = self.install(health=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state['containers']['test-mux']['Image'], fixtures.OLD)
        self.assertTrue(self.state['containers']['test-mux']['State']['Running'])
        self.assert_saved()

    def test_newer_version_is_preserved_without_candidate_creation(self):
        self.state['containers']['test-mux']['Config']['Labels']['org.opencontainers.image.version'] = '0.9.89'
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.status['phase'], 'current')
        self.assertFalse(any(a[0] in ('load', 'create', 'run', 'stop') for a in self.calls))
        self.assert_saved()

    def test_same_version_remains_current_without_reinstalling(self):
        self.state['containers']['test-mux']['Config']['Labels']['org.opencontainers.image.version'] = '0.9.88'
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.status['phase'], 'current')
        self.assertFalse(any(a[0] in ('load', 'create', 'run', 'stop') for a in self.calls))

    def test_tampered_archive_cannot_reach_candidate_inspection(self):
        self.archive.write_bytes(b'tampered')
        self.assert_candidate_failure_preserves_runtime(self.install())
        self.assertFalse(any(a[0] in ('load', 'create') for a in self.calls))

    def test_asset_parser_rejects_unsafe_paths_empty_files_and_non_html_index(self):
        original = self.index.read_text()
        for reference in ('/app.js', '//other.invalid/app.js', '../app.js', 'nested/app.js',
                          'https://other.invalid/app.js', 'app%2Ejs'):
            with self.subTest(reference=reference):
                self.index.write_text(original.replace('app.js?v=127', reference))
                result = self.run_shell('web_asset_tree "$TEST_ROOT/assets"')
                self.assertNotEqual(result.returncode, 0)
        self.index.write_text(original)
        (self.assets / 'app.js').write_bytes(b'')
        self.assertNotEqual(self.run_shell('web_asset_tree "$TEST_ROOT/assets"').returncode, 0)
        self.index.write_text('{"error":"not found"}')
        self.assertNotEqual(self.run_shell('web_asset_tree "$TEST_ROOT/assets"').returncode, 0)

    def test_asset_symlink_cannot_escape_candidate_directory(self):
        (self.assets / 'app.js').unlink()
        (self.assets / 'app.js').symlink_to(self.saved)
        self.assert_candidate_failure_preserves_runtime(self.install())


if __name__ == '__main__':
    unittest.main()
