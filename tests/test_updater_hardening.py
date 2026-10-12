"""Regression tests for updater hardening: loopback config, downgrade floor,
interrupted-install recovery, bounded network calls, safe rollback, temp-dir
cleanup, busy-status reset and private archive copies."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / '5tratmux-update'
OLD = 'sha256:' + 'a' * 64
NEW = 'sha256:' + 'b' * 64
CUR = 'sha256:' + 'c' * 64

DOCKER = r'''
import hashlib, json, os, sys
from pathlib import Path
r=Path(os.environ['TEST_ROOT']); p=r/'docker.json'; state=json.loads(p.read_text()); a=sys.argv[1:]
with (r/'calls.jsonl').open('a') as f: f.write(json.dumps(a)+'\n')
containers=state['containers']; name=a[-1]
def save(): p.write_text(json.dumps(state))
def fail(): save(); sys.exit(1)
if a[:2]==['container','inspect']:
 if name not in containers: fail()
 c=containers[name]
 fmt=a[a.index('--format')+1] if '--format' in a else None
 if fmt is None: print(json.dumps([c]))
 elif fmt=='{{json .}}': print(json.dumps(c))
 elif fmt=='{{.Image}}': print(c['Image'])
 elif fmt=='{{.Config.Image}}': print(c['Image'])
 elif fmt=='{{.State.Status}}': print(c['State']['Status'])
 elif 'org.opencontainers.image.version' in fmt: print(c['Config']['Labels'].get('org.opencontainers.image.version','<no value>'))
 elif '.Config.Env' in fmt: pass
 else: raise AssertionError(fmt)
elif a[:2]==['container','ls']:
 if state.get('daemonDown'): fail()
 print('\n'.join(containers))
elif a[:2]==['image','inspect']:
 if '--format' in a: print('MAIN')
 else: print('{}')
elif a[:2]==['image','tag']: pass
elif a[0]=='load':
 data=Path(a[a.index('--input')+1]).read_bytes()
 with (r/'loaded.jsonl').open('a') as f: f.write(json.dumps({'path':a[a.index('--input')+1],'sha':hashlib.sha256(data).hexdigest()})+'\n')
elif a[0]=='update':
 containers[name]['HostConfig']['RestartPolicy']['Name']=a[1].split('=',1)[1]
elif a[0]=='stop':
 containers[name]['State'].update(Running=False,Status='exited')
elif a[0]=='restart':
 containers[name]['State'].update(Running=True,Status='running')
elif a[0]=='rename':
 if a[2] in containers: fail()
 containers[a[2]]=containers.pop(a[1])
elif a[:2]==['container','rm']:
 if name not in containers: fail()
 containers.pop(name)
elif a[0] in ('create','run'):
 if state.get('failCreate'): fail()
 n=a[a.index('--name')+1]
 if n in containers: fail()
 rollback=name=='5tratmux:rollback'
 containers[n]={'Id':'d'*64,'Image':'sha256:'+('a' if rollback else 'b')*64,'State':{'Running':a[0]=='run','Restarting':False,'Paused':False,'Dead':False,'Status':'running' if a[0]=='run' else 'created'},'HostConfig':{'RestartPolicy':{'Name':a[a.index('--restart')+1]}},'Config':{'Labels':{'org.opencontainers.image.version':'0.9.67' if rollback else state.get('newVersion','0.9.68')}}}
elif a[0]=='start':
 if name not in containers: fail()
 containers[name]['State'].update(Running=True,Status='running')
else: raise AssertionError(a)
save()
'''


def container(image, version, running=True, ident='c'):
    labels = {} if version is None else {'org.opencontainers.image.version': version}
    return {'Id': ident * 64, 'Image': image,
            'State': {'Running': running, 'Restarting': False, 'Paused': False, 'Dead': False,
                      'Status': 'running' if running else 'exited'},
            'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped'}},
            'Config': {'Labels': labels}}


class UpdaterHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.bundle = self.root/'bundle'; self.bundle.mkdir()
        self.scratch = self.root/'tmpdir'; self.scratch.mkdir()
        (self.root/'functions.sh').write_text(SOURCE.read_text().split('case "${1:---check}" in')[0])
        (self.root/'docker.py').write_text(DOCKER)
        self.state = {'containers': {'test-mux': container(OLD, '0.9.67')}}
        self.env = dict(os.environ, TEST_ROOT=str(self.root), MUX_CONTAINER_NAME='test-mux',
            MUX_RUNTIME_DIR=str(self.root), MUX_STATUS_FILE=str(self.root/'status.json'),
            MUX_STATE_DIR=str(self.root/'data'), MUX_POWER_STATE_FILE=str(self.root/'power.json'),
            MUX_UPDATER_ENV_FILE=str(self.root/'absent.env'), MUX_DNS_CONFIG_FILE=str(self.root/'absent.json'),
            MUX_CONFIG_DIR=str(self.root/'etc'), MUX_CONTROLLER_TOKEN_FILE=str(self.root/'etc'/'token'),
            TMPDIR=str(self.scratch))
        (self.root/'power.json').write_text('{"desired":"on"}')
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.root/'key')],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(self.root/'key'),'-pubout','-out',str(self.root/'pub')],check=True,capture_output=True)
        self.publish('0.9.68')

    def publish(self, version, payload=b'fixture archive'):
        for old in self.bundle.glob('*.oci.tar.gz'): old.unlink()
        self.archive = self.bundle/f'5tratmux-{version}-amd64.oci.tar.gz'; self.archive.write_bytes(payload)
        self.digest = hashlib.sha256(payload).hexdigest()
        manifest = {'version': version, 'channel': 'MAIN', 'images': {'amd64': {
            'image': f'test:{version}', 'url': 'https://never.invalid/image', 'sha256': self.digest}}}
        path = self.bundle/'5tratmux-release.json'; path.write_text(json.dumps(manifest))
        subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(self.root/'key'),'-in',str(path),
                        '-out',str(path)+'.sig'],check=True,capture_output=True)
        self.state['newVersion'] = version

    def run_shell(self, action, *, health=True, extra=''):
        (self.root/'docker.json').write_text(json.dumps(self.state))
        script = '''source "$1"
require_root() { :; }; require_commands() { :; }; ensure_config() { :; }
write_public_key() { PUBLIC_KEY_FILE="$TEST_ROOT/pub"; }
architecture() { echo amd64; }; enable_watchdog_service() { :; }; install() { :; }
container_mounts() { printf -- "--mount\\ntype=bind,src=/fixture,dst=/fixture,readonly\\n"; }
if [[ "$(uname -s)" == Darwin ]]; then sha256sum() { shasum -a 256 "$@"; }; fi
docker() { python3 "$TEST_ROOT/docker.py" "$@"; }
curl() { printf '%s\\n' "$*" >> "$TEST_ROOT/curl.log"; return 99; }
sleep() { :; }
# BSD mktemp ignores TMPDIR without a template; keep work dirs observable.
mktemp() { command mktemp -d "$TMPDIR/tmp.XXXXXXXX"; }
wait_for_health() { printf health >> "$TEST_ROOT/health"; return ''' + ('0' if health else '1') + '''; }
''' + extra + '\n' + action
        result = subprocess.run(['bash','-c',script,'test',str(self.root/'functions.sh')],env=self.env,
                                capture_output=True,text=True,timeout=30)
        self.state = json.loads((self.root/'docker.json').read_text())
        status = self.root/'status.json'
        self.status = json.loads(status.read_text()) if status.exists() else None
        calls = self.root/'calls.jsonl'
        self.calls = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        loaded = self.root/'loaded.jsonl'
        self.loaded = [json.loads(line) for line in loaded.read_text().splitlines()] if loaded.exists() else []
        return result

    def install(self, **kwargs):
        return self.run_shell('install_release "$TEST_ROOT/bundle"', **kwargs)

    # 1. Loopback config and migration -------------------------------------
    def config_run(self, existing=None):
        config = self.root/'etc'/'5tratmux.env'
        if existing is not None:
            config.parent.mkdir(exist_ok=True); config.write_text(existing)
        code = 'source "$1"\nchown() { :; }; detect_host_ip() { echo 192.0.2.5; }\nensure_config\n'
        result = subprocess.run(['bash','-c',code,'test',str(self.root/'functions.sh')],env=self.env,
                                capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        return config.read_text().splitlines()

    def test_new_config_binds_loopback(self):
        lines = self.config_run()
        self.assertIn('APP_HOST=127.0.0.1', lines)
        self.assertNotIn('APP_HOST=0.0.0.0', lines)
        self.assertIn('APP_PUBLIC_HOST=192.0.2.5', lines)
        self.assertTrue(any(l.startswith('MUX_LICENSING_PUBLIC_KEY=') and len(l) > 30 for l in lines))

    def test_existing_lan_config_is_migrated_and_key_added(self):
        lines = self.config_run('APP_HOST=0.0.0.0\nAPP_PORT=21222\nAPP_PUBLIC_HOST=10.0.0.9\nCUSTOM=kept\n')
        self.assertIn('APP_HOST=127.0.0.1', lines); self.assertNotIn('APP_HOST=0.0.0.0', lines)
        self.assertIn('APP_PUBLIC_HOST=192.0.2.5', lines); self.assertIn('CUSTOM=kept', lines)
        keys = [l for l in lines if l.startswith('MUX_LICENSING_PUBLIC_KEY=')]
        self.assertEqual(keys, ['MUX_LICENSING_PUBLIC_KEY=I_aujMd069Ki6ZYDw-qhQDQWM0JX5ymizbg7pqVakkE'])
        # Idempotent.
        self.assertEqual(self.config_run(None), lines)

    def test_existing_key_and_explicit_lan_opt_in_are_preserved(self):
        lines = self.config_run('APP_HOST=0.0.0.0\nMUX_HTTP_ALLOW_LAN=1\nMUX_LICENSING_PUBLIC_KEY=operator-key\n')
        self.assertIn('APP_HOST=0.0.0.0', lines)
        self.assertEqual([l for l in lines if l.startswith('MUX_LICENSING_PUBLIC_KEY=')],
                         ['MUX_LICENSING_PUBLIC_KEY=operator-key'])

    # 2. Downgrade floor ----------------------------------------------------
    def test_missing_container_cannot_install_older_than_recorded_floor(self):
        self.state['containers'] = {}
        (self.root/'installed-version').write_text('0.9.70\n')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('older than previously installed', self.status['message'])
        self.assertFalse(any(a[0] in ('load','create','run') for a in self.calls))

    def test_unlabelled_container_cannot_be_downgraded(self):
        self.state['containers']['test-mux'] = container(CUR, None)
        (self.root/'highest-installed-version').write_text('0.9.70\n')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state['containers']['test-mux']['Image'], CUR)
        self.assertFalse(any(a[0] in ('load','stop','rename','create','run') for a in self.calls))

    def test_explicit_allow_downgrade_installs_and_resets_floor(self):
        self.state['containers'] = {}
        (self.root/'highest-installed-version').write_text('0.9.70\n')
        result = self.run_shell('ALLOW_DOWNGRADE=1; install_release "$TEST_ROOT/bundle"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root/'highest-installed-version').read_text().strip(), '0.9.68')

    def test_same_version_repair_and_upgrade_record_highest(self):
        self.state['containers'] = {}
        (self.root/'highest-installed-version').write_text('0.9.68\n')
        result = self.install(); self.assertEqual(result.returncode, 0, result.stderr)
        self.publish('0.9.69')
        result = self.install(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root/'highest-installed-version').read_text().strip(), '0.9.69')
        self.assertEqual((self.root/'installed-version').read_text().strip(), '0.9.69')

    def test_cli_rejects_unknown_install_argument(self):
        code = SOURCE.read_text()
        self.assertIn('--allow-downgrade', code)
        result = subprocess.run(['bash', str(SOURCE), '--install', '--bogus'], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('usage', result.stderr)

    # 3. Interrupted install recovery ---------------------------------------
    def interrupted(self):
        self.state['containers'] = {
            'test-mux-previous-100': container(CUR, '0.9.60', running=False, ident='e'),
            'test-mux-previous-200': container(OLD, '0.9.68', running=False, ident='f'),
        }

    def assert_restored(self):
        restored = self.state['containers']['test-mux']
        self.assertEqual(restored['Id'], 'f' * 64)
        self.assertTrue(restored['State']['Running'])
        self.assertEqual(restored['HostConfig']['RestartPolicy']['Name'], 'unless-stopped')
        first_rename = next(i for i, a in enumerate(self.calls) if a[0] == 'rename')
        self.assertEqual(self.calls[first_rename], ['rename', 'test-mux-previous-200', 'test-mux'])
        self.assertFalse(any(a[0] in ('load','create','run') for a in self.calls))
        self.assertFalse((self.root/'curl.log').exists())

    def test_bootstrap_restores_newest_previous_container_without_download(self):
        self.interrupted()
        result = self.run_shell('bootstrap_release'); self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored()
        self.assertIn('test-mux-previous-100', self.state['containers'])

    def test_install_restores_before_verifying_or_downloading(self):
        self.interrupted()
        result = self.install(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored()
        self.assertEqual(self.status['phase'], 'current')

    def test_watchdog_restores_previous_container(self):
        self.interrupted()
        extra = ('health_ready() { local n=0; [[ -r "$TEST_ROOT/hc" ]] && n=$(cat "$TEST_ROOT/hc"); '
                 'echo $((n+1)) > "$TEST_ROOT/hc"; (( n >= 2 )); }; watchdog_log() { :; }')
        result = self.run_shell('watchdog_once', extra=extra); self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored()

    def test_restore_does_not_guess_when_daemon_is_down(self):
        self.interrupted(); self.state['daemonDown'] = True
        result = self.run_shell('bootstrap_release')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(a[0] == 'rename' for a in self.calls))

    # 4. Bounded network calls ----------------------------------------------
    def test_every_curl_invocation_is_time_bounded(self):
        text = SOURCE.read_text()
        commands = []
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if re.search(r'(^|[\s(])curl\s+--', line):
                block = line
                while block.rstrip().endswith('\\'):
                    index += 1; block += lines[index]
                commands.append(block)
        self.assertGreaterEqual(len(commands), 5)
        for command in commands:
            self.assertIn('--connect-timeout', command)
            self.assertIn('--max-time', command)

    def test_wait_for_health_honours_overall_deadline(self):
        self.env.update(MUX_HEALTH_ATTEMPTS='100000', MUX_HEALTH_DEADLINE_SECONDS='1')
        code = ('source "$1"\ncurl() { printf "%s\\n" "$*" >> "$TEST_ROOT/curl.log"; return 7; }\n'
                'sleep() { SECONDS=$((SECONDS+1)); }\nwait_for_health')
        result = subprocess.run(['bash','-c',code,'test',str(self.root/'functions.sh')],env=self.env,
                                capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode, 0)
        probes = (self.root/'curl.log').read_text().splitlines()
        self.assertLess(len(probes), 5)
        self.assertIn('--max-time', probes[0])

    # 5. Safe rollback ------------------------------------------------------
    def test_failed_rollback_restores_current_running_container(self):
        self.state['containers']['test-mux'] = container(NEW, '0.9.68', ident='9')
        self.state['failCreate'] = True
        result = self.run_shell('rollback_release')
        self.assertNotEqual(result.returncode, 0)
        current = self.state['containers']['test-mux']
        self.assertEqual(current['Id'], '9' * 64); self.assertTrue(current['State']['Running'])
        self.assertEqual(list(self.state['containers']), ['test-mux'])
        self.assertFalse(any(a[:2] == ['container','rm'] and 'test-mux' in a and a[-1] != 'test-mux' for a in self.calls))
        self.assertEqual(self.status['phase'], 'failed')

    def test_failed_rollback_health_restores_current_container(self):
        self.state['containers']['test-mux'] = container(NEW, '0.9.68', ident='9')
        result = self.run_shell('rollback_release', health=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state['containers']['test-mux']['Id'], '9' * 64)
        self.assertTrue(self.state['containers']['test-mux']['State']['Running'])
        self.assertIn('current release was restored', self.status['message'])

    def test_successful_rollback_replaces_current_container(self):
        self.state['containers']['test-mux'] = container(NEW, '0.9.68', ident='9')
        result = self.run_shell('rollback_release'); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.state['containers']), ['test-mux'])
        self.assertEqual(self.state['containers']['test-mux']['Image'], OLD)
        self.assertEqual(self.status['phase'], 'healthy')

    # 6. Temp dir cleanup ---------------------------------------------------
    def test_work_directory_is_removed_after_success_and_failure(self):
        self.archive.write_bytes(b'tampered')
        result = self.install(); self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.archive.write_bytes(b'fixture archive')
        result = self.install(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.scratch.iterdir()), [])

    # 7. Busy status reset --------------------------------------------------
    def test_unexpected_failure_clears_busy_status(self):
        result = self.run_shell('install_release "$TEST_ROOT/bundle"',
                                extra='manifest_value() { return 3; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.status['phase'], 'failed')
        self.assertFalse(self.status['busy'])

    def test_specific_die_message_is_not_overwritten(self):
        self.archive.write_bytes(b'tampered')
        result = self.install(); self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.status['message'], 'OCI archive checksum verification failed')

    # 8. Private archive copy -----------------------------------------------
    def test_bundle_archive_is_hashed_and_loaded_from_private_copy(self):
        # Swap the bundle file after verification: the loaded bytes must not change.
        extra = ('_real_sha() { if [[ "$(uname -s)" == Darwin ]]; then shasum -a 256 "$@"; else command sha256sum "$@"; fi; }\n'
                 'sha256sum() { _real_sha "$@"; local rc=$?; printf evil > "$TEST_ROOT/bundle/5tratmux-0.9.68-amd64.oci.tar.gz"; return $rc; }')
        result = self.install(extra=extra); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.loaded), 1)
        self.assertEqual(self.loaded[0]['sha'], self.digest)
        loaded = os.path.realpath(self.loaded[0]['path'])
        self.assertFalse(loaded.startswith(os.path.realpath(self.bundle)))
        self.assertTrue(loaded.startswith(os.path.realpath(self.scratch)), loaded)


if __name__ == '__main__':
    unittest.main()
