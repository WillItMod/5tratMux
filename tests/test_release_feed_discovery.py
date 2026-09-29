"""Actual updater startup with isolated feed files; no Docker/network or install."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / '5tratmux-update'
PUBLIC = 'https://github.com/WillItMod/5tratMux/releases/latest/download/5tratmux-release.json'
PIN = 'https://github.com/WillItMod/5tratMux/releases/download/v0.9.54/5tratmux-release.json'
HEADER = '# Managed by 5tratumOS update handoff\n'


class ReleaseFeedDiscoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.feed = self.root / 'updater.env'; self.marker = self.root / 'pending.json'
        self.prefix = SOURCE.read_text().split('LICENSING_URL=', 1)[0]
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('MUX_')}
        self.env.update(MUX_UPDATER_ENV_FILE=str(self.feed), MUX_OS_HANDOFF_MARKER=str(self.marker))

    def write_pin(self, url=PIN, header=HEADER, signature=None, extra=''):
        self.feed.write_text(f'{header}MUX_MANIFEST_URL={url}\nMUX_SIGNATURE_URL={signature or url + ".sig"}\n{extra}')

    def resolve(self):
        before = self.feed.read_bytes() if self.feed.exists() else None
        result = subprocess.run(['bash', '-c', self.prefix + '\nprintf "%s\\n%s\\n" "$MANIFEST_URL" "$SIGNATURE_URL"'],
                                env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.feed.read_bytes() if self.feed.exists() else None, before)
        return result.stdout.splitlines()

    def test_old_managed_public_pin_discovers_latest_without_deleting_file(self):
        self.write_pin()
        self.assertEqual(self.resolve(), [PUBLIC, PUBLIC + '.sig'])

    def test_active_handoff_including_broken_link_retains_exact_release(self):
        self.write_pin(); self.marker.write_text('{}')
        self.assertEqual(self.resolve(), [PIN, PIN + '.sig'])
        self.marker.unlink(); self.marker.symlink_to(self.root / 'absent')
        self.assertEqual(self.resolve(), [PIN, PIN + '.sig'])

    def test_operator_private_dev_and_extended_files_are_not_reinterpreted(self):
        for url, header, extra in [
            (PIN, '', ''),
            ('https://operator.invalid/release.json', HEADER, ''),
            (PIN.replace('v0.9.54/', 'v0.9.59-dev/'), HEADER, ''),
            (PIN, HEADER, 'MUX_CONTAINER_NAME=private-preview\n'),
        ]:
            with self.subTest(url=url, header=header, extra=extra):
                self.write_pin(url, header, extra=extra)
                self.assertEqual(self.resolve(), [url, url + '.sig'])

    def test_nonmatching_signature_and_symlinked_feed_are_preserved(self):
        custom_signature = 'https://operator.invalid/signed.sig'
        self.write_pin(signature=custom_signature)
        self.assertEqual(self.resolve(), [PIN, custom_signature])
        self.write_pin(); real = self.root / 'operator.env'; self.feed.rename(real); self.feed.symlink_to(real)
        self.assertEqual(self.resolve(), [PIN, PIN + '.sig'])

    def test_explicit_feed_override_survives_ignored_managed_pin(self):
        self.write_pin()
        self.env.update(MUX_MANIFEST_URL='https://operator.invalid/explicit.json', MUX_SIGNATURE_URL='https://operator.invalid/explicit.sig')
        self.assertEqual(self.resolve(), [self.env['MUX_MANIFEST_URL'], self.env['MUX_SIGNATURE_URL']])

    def test_missing_feed_uses_public_default(self):
        self.assertEqual(self.resolve(), [PUBLIC, PUBLIC + '.sig'])


if __name__ == '__main__':
    unittest.main()
