"""Execute the real updater functions against a persistent Docker model."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / '5tratmux-update'
OLD = 'sha256:' + 'a' * 64
NEW = 'sha256:' + 'b' * 64

DOCKER = r'''
import json, os, sys
from pathlib import Path
r=Path(os.environ['TEST_ROOT']); p=r/'docker.json'; state=json.loads(p.read_text()); a=sys.argv[1:]
with (r/'calls.jsonl').open('a') as f: f.write(json.dumps(a)+'\n')
containers=state['containers']; name=a[-1]
def save(): p.write_text(json.dumps(state))
def fail(): save(); sys.exit(1)
if a[:2]==['container','inspect']:
 if name not in containers: fail()
 c=containers[name]
 if '--format' not in a: print(json.dumps([c]))
 else:
  fmt=a[a.index('--format')+1]
  if fmt=='{{json .}}': print(json.dumps(c))
  elif fmt=='{{.Image}}': print(c['Image'])
  elif 'org.opencontainers.image.version' in fmt: print(c['Config']['Labels']['org.opencontainers.image.version'])
  else: raise AssertionError(fmt)
elif a[:2]==['container','ls']:
 if state.get('daemonDown'): fail()
 print('\n'.join(containers))
elif a[:2]==['image','inspect']:
 if '--format' in a: print('MAIN')
 else: print('{}')
elif a[:2]==['image','tag'] or a[0]=='load': pass
elif a[0]=='update':
 if state.get('failPolicy'): fail()
 containers[name]['HostConfig']['RestartPolicy']['Name']='no'
elif a[0]=='stop':
 if state.get('failStop'): fail()
 containers[name]['State'].update(Running=False,Status='exited')
elif a[0]=='rename': containers[a[2]]=containers.pop(a[1])
elif a[:2]==['container','rm']:
 if state.get('failRemove') or name not in containers: fail()
 containers.pop(name)
elif a[0] in ('create','run'):
 if state.get('failCreate'): fail()
 n=a[a.index('--name')+1]; image='sha256:' + ('a' if name=='5tratmux:rollback' else 'b')*64
 version='0.9.67' if name=='5tratmux:rollback' else '0.9.68'
 containers[n]={'Id':'d'*64,'Image':image,'State':{'Running':a[0]=='run','Restarting':False,'Paused':False,'Dead':False,'Status':'running' if a[0]=='run' else 'created'},'HostConfig':{'RestartPolicy':{'Name':a[a.index('--restart')+1]}},'Config':{'Labels':{'org.opencontainers.image.version':version}}}
 if state.get('badCreatedState'): containers[n]['State']['Restarting']=True
elif a[0]=='start': containers[name]['State'].update(Running=True,Status='running')
else: raise AssertionError(a)
save()
'''


class DisabledUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.bundle = self.root/'bundle'; self.bundle.mkdir()
        (self.root/'functions.sh').write_text(SOURCE.read_text().split('case "${1:---check}" in')[0])
        (self.root/'docker.py').write_text(DOCKER)
        self.state = {'containers': {'test-mux': {'Id':'c'*64,'Image':OLD,
            'State':{'Running':False,'Restarting':False,'Paused':False,'Dead':False,'Status':'exited'},
            'HostConfig':{'RestartPolicy':{'Name':'no'}},
            'Config':{'Labels':{'org.opencontainers.image.version':'0.9.67'}}}}}
        self.env = dict(os.environ, TEST_ROOT=str(self.root), MUX_CONTAINER_NAME='test-mux',
            MUX_RUNTIME_DIR=str(self.root), MUX_STATUS_FILE=str(self.root/'status.json'),
            MUX_STATE_DIR=str(self.root/'data'), MUX_POWER_STATE_FILE=str(self.root/'power.json'),
            MUX_UPDATER_ENV_FILE=str(self.root/'absent.env'), MUX_DNS_CONFIG_FILE=str(self.root/'absent.json'),
            MUX_UPDATE_OPERATION_ID='1'*32)
        (self.root/'power.json').write_text('{"desired":"off"}')
        archive=self.bundle/'5tratmux-0.9.68-amd64.oci.tar.gz'; archive.write_bytes(b'fixture archive')
        manifest={'version':'0.9.68','channel':'MAIN','images':{'amd64':{'image':'test:0.9.68','url':'https://never.invalid/image','sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}}}
        self.manifest=self.bundle/'5tratmux-release.json'; self.manifest.write_text(json.dumps(manifest))
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.root/'key')],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(self.root/'key'),'-pubout','-out',str(self.root/'pub')],check=True,capture_output=True)
        subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(self.root/'key'),'-in',str(self.manifest),'-out',str(self.manifest)+'.sig'],check=True,capture_output=True)

    def run_update(self, action='install_release "$TEST_ROOT/bundle"', *, health=True):
        (self.root/'docker.json').write_text(json.dumps(self.state))
        script='''source "$1"
require_root() { :; }; require_commands() { :; }; ensure_config() { :; }
write_public_key() { PUBLIC_KEY_FILE="$TEST_ROOT/pub"; }
architecture() { echo amd64; }; enable_watchdog_service() { :; }; install() { :; }
container_mounts() { printf -- "--mount\\ntype=bind,src=/fixture,dst=/fixture,readonly\\n"; }
if [[ "$(uname -s)" == Darwin ]]; then sha256sum() { shasum -a 256 "$@"; }; fi
docker() { python3 "$TEST_ROOT/docker.py" "$@"; }
curl() { printf health >> "$TEST_ROOT/health"; return 99; }
wait_for_health() { printf health >> "$TEST_ROOT/health"; return '''+('0' if health else '1')+'''; }
'''+action
        result=subprocess.run(['bash','-c',script,'test',str(self.root/'functions.sh')],env=self.env,capture_output=True,text=True,timeout=15)
        self.state=json.loads((self.root/'docker.json').read_text())
        self.status=json.loads((self.root/'status.json').read_text())
        calls=self.root/'calls.jsonl'
        self.calls=[json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        return result

    def assert_off(self, version='0.9.68', image=NEW):
        self.assertEqual(self.status['phase'],'powered_off')
        self.assertEqual(self.status['version'],version)
        self.assertEqual(self.status['operationId'],'1'*32)
        self.assertEqual(self.status['power'],{'desired':'off','verified':True,'containerPresent':True,
            'containerName':'test-mux','containerId':self.state['containers']['test-mux']['Id'],'imageId':image,'running':False,'restartPolicy':'no'})
        self.assertFalse((self.root/'health').exists())
        self.assertFalse(any(a[0] in ('run','start','restart') for a in self.calls))

    def test_off_new_signed_install_creates_without_activation(self):
        result=self.run_update(); self.assertEqual(result.returncode,0,result.stderr); self.assert_off()
        self.assertEqual((self.root/'installed-version').read_text().strip(),'0.9.68')
        self.assertTrue(any(a[0]=='create' and '--read-only' in a for a in self.calls))

    def test_off_current_install_is_verified_without_activation(self):
        self.state['containers']['test-mux']['Config']['Labels']['org.opencontainers.image.version']='0.9.68'
        result=self.run_update(); self.assertEqual(result.returncode,0,result.stderr); self.assert_off(image=OLD)
        self.assertFalse(any(a[0] in ('load','create') for a in self.calls))

    def test_off_explicit_rollback_does_not_start_or_health_probe(self):
        result=self.run_update('rollback_release'); self.assertEqual(result.returncode,0,result.stderr)
        self.assert_off('0.9.67',OLD)

    def test_failed_creation_restores_old_container_without_starting(self):
        self.state['failCreate']=True
        result=self.run_update(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.status['phase'],'failed'); self.assertEqual(self.state['containers']['test-mux']['Image'],OLD)
        self.assertFalse(self.state['containers']['test-mux']['State']['Running'])
        self.assertFalse(any(a[0] in ('run','start','restart') for a in self.calls))
        self.assertFalse(any(a[:2]==['container','rm'] for a in self.calls))

    def test_stop_or_policy_failure_never_reports_off_success(self):
        for flag in ('failStop','failPolicy'):
            with self.subTest(flag=flag):
                self.state[flag]=True
                result=self.run_update('hold_powered_off')
                self.assertNotEqual(result.returncode,0); self.assertEqual(self.status['phase'],'failed')
                self.state.pop(flag)

    def test_install_stop_failure_keeps_previous_container_and_reports_failure(self):
        self.state['failStop']=True; before=json.loads(json.dumps(self.state['containers']))
        result=self.run_update(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.status['phase'],'failed')
        self.assertEqual(self.state['containers'],before)
        self.assertFalse(any(a[0] in ('rename','create','run','start') for a in self.calls))

    def test_inconsistent_created_state_is_refused_and_old_container_restored(self):
        self.state['badCreatedState']=True
        result=self.run_update(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.status['phase'],'failed'); self.assertEqual(self.state['containers']['test-mux']['Image'],OLD)

    def test_on_install_keeps_health_and_running_behavior(self):
        (self.root/'power.json').write_text('{"desired":"on"}')
        result=self.run_update(); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.status['phase'],'healthy'); self.assertTrue(self.state['containers']['test-mux']['State']['Running'])
        self.assertTrue((self.root/'health').exists()); self.assertTrue(any(a[0]=='run' for a in self.calls))

    def test_on_health_failure_restores_running_old_container_and_reports_failure(self):
        (self.root/'power.json').write_text('{"desired":"on"}')
        result=self.run_update(health=False); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.status['phase'],'failed'); self.assertEqual(self.state['containers']['test-mux']['Image'],OLD)
        self.assertTrue(self.state['containers']['test-mux']['State']['Running'])

    def test_bootstrap_and_watchdog_verify_off_and_surface_stop_errors(self):
        for action in ('bootstrap_release','watchdog_once'):
            with self.subTest(action=action):
                result=self.run_update(action); self.assertEqual(result.returncode,0,result.stderr); self.assert_off('0.9.67',OLD)
                self.state['failStop']=True
                result=self.run_update(action); self.assertNotEqual(result.returncode,0); self.assertEqual(self.status['phase'],'failed')
                self.state.pop('failStop')

    def test_absence_is_distinguished_from_daemon_failure(self):
        self.state['containers']={}
        result=self.run_update('bootstrap_release'); self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.status['power']['containerPresent']); self.assertEqual(self.status['version'],'not-installed')
        self.state['daemonDown']=True
        result=self.run_update('bootstrap_release'); self.assertNotEqual(result.returncode,0); self.assertEqual(self.status['phase'],'failed')

    def test_operation_receipt_survives_unidentified_watchdog_status(self):
        result=self.run_update(); self.assertEqual(result.returncode,0,result.stderr)
        receipt=self.root/'os-update-status.json'; original=receipt.read_bytes()
        self.assertEqual(json.loads(original),self.status)
        self.env.pop('MUX_UPDATE_OPERATION_ID')
        self.state['failStop']=True
        result=self.run_update('watchdog_once'); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.status['phase'],'failed')
        self.assertNotIn('operationId',self.status)
        self.assertEqual(receipt.read_bytes(),original)

    def test_explicit_operation_result_path_binds_failure(self):
        receipt=self.root/'operation.json'
        self.env['MUX_UPDATE_RESULT_FILE']=str(receipt)
        self.state['failCreate']=True
        result=self.run_update(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(receipt.read_bytes()),self.status)
        self.assertEqual(self.status['phase'],'failed')
        self.assertEqual(self.status['operationId'],'1'*32)
        self.assertFalse((self.root/'os-update-status.json').exists())

    def test_first_install_creation_failure_does_not_claim_restoration(self):
        self.state['containers']={}; self.state['failCreate']=True
        result=self.run_update(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.status['phase'],'failed')
        self.assertIn('no previous container was available',self.status['message'])
        self.assertEqual(self.state['containers'],{})

    def test_invalid_signature_cannot_mutate_off_container(self):
        Path(str(self.manifest)+'.sig').write_bytes(b'not a signature')
        before=json.loads(json.dumps(self.state))
        result=self.run_update(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.state,before)
        self.assertEqual(self.status['phase'],'failed')
        self.assertFalse(any(a[0] in ('load','create','run','stop','update','rename') for a in self.calls))

    def test_tampered_signed_archive_cannot_mutate_off_container(self):
        (self.bundle/'5tratmux-0.9.68-amd64.oci.tar.gz').write_bytes(b'tampered')
        before=json.loads(json.dumps(self.state))
        result=self.run_update(); self.assertNotEqual(result.returncode,0); self.assertEqual(self.state,before)
        self.assertFalse(any(a[0] in ('load','create','run','stop','update','rename') for a in self.calls))


if __name__=='__main__': unittest.main()
