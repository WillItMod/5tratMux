"""The release refresh may change metadata while preserving protected bytes."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('web_refresh', Path(__file__).resolve().parents[1] / 'release/build-web-refresh.py')
REFRESH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFRESH)


class WebRefreshRecipeTests(unittest.TestCase):
    def setUp(self):
        self.parent = {'imageId': 'sha256:parent', 'nativeBinarySha256': 'native',
                       'browserFiles': {'index.html': 'index', 'app.css': 'css', 'app.js': 'js'},
                       'config': {'architecture': 'amd64', 'os': 'linux',
                                  'rootfs': {'type': 'layers', 'diff_ids': ['sha256:layer']},
                                  'config': {'Env': ['APP_VERSION=0.9.87', 'APP_CHANNEL=MAIN', 'STATE_DIR=/data/ui/state'],
                                             'Entrypoint': ['/app/5tratmux'], 'WorkingDir': '/app',
                                             'Labels': {'org.opencontainers.image.version': '0.9.87'}}}}
        self.candidate = copy.deepcopy(self.parent)
        self.candidate['config']['config']['Env'][0] = 'APP_VERSION=0.9.88'
        self.candidate['config']['config']['Labels'].update({
            'org.opencontainers.image.version': '0.9.88',
            'com.5tratumos.metadata-parent-config': self.parent['imageId'],
            'com.5tratumos.native-source-revision': REFRESH.SOURCE_REVISION,
            'com.5tratumos.release-refresh': 'metadata-only'})

    def test_only_declared_version_metadata_is_accepted(self):
        REFRESH.verify_refresh(self.parent, self.candidate, '0.9.88')

    def test_native_binary_browser_layer_and_runtime_configuration_changes_are_rejected(self):
        for defect in ('native', 'browser', 'layer', 'entrypoint', 'state', 'channel', 'platform'):
            with self.subTest(defect=defect):
                value = copy.deepcopy(self.candidate)
                if defect == 'native': value['nativeBinarySha256'] = 'different'
                elif defect == 'browser': value['browserFiles']['app.js'] = 'different'
                elif defect == 'layer': value['config']['rootfs']['diff_ids'].append('extra')
                elif defect == 'entrypoint': value['config']['config']['Entrypoint'] = ['/bin/sh']
                elif defect == 'state': value['config']['config']['Env'][2] = 'STATE_DIR=/other'
                elif defect == 'channel': value['config']['config']['Env'][1] = 'APP_CHANNEL=PRIVATE'
                elif defect == 'platform': value['config']['architecture'] = 'arm64'
                with self.assertRaises(ValueError): REFRESH.verify_refresh(self.parent, value, '0.9.88')

    def test_both_architectures_and_distribution_channels_have_mandatory_parent_pins(self):
        self.assertEqual(set(REFRESH.PARENTS), {'main', 'dev'})
        for value in REFRESH.PARENTS.values():
            self.assertEqual(set(value['images']), {'amd64', 'arm64'})
            for digest in value['images'].values(): self.assertRegex(digest, r'^[0-9a-f]{64}$')

    def archive_fixture(self, path, *, corrupt=False, compressed=False):
        def add(archive, name, data):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w') as archive:
            for name in ('app/5tratmux', 'app/static/index.html', 'app/static/app.css', 'app/static/app.js'):
                add(archive, name, name.encode())
        layer_bytes = layer.getvalue()
        layer_digest = hashlib.sha256(layer_bytes).hexdigest()
        config = copy.deepcopy(self.parent['config'])
        config['rootfs']['diff_ids'] = ['sha256:' + layer_digest]
        config_bytes = json.dumps(config).encode()
        config_digest = hashlib.sha256(config_bytes).hexdigest()
        manifest = json.dumps({'schemaVersion': 2, 'config': {'digest': 'sha256:' + config_digest},
                               'layers': [{'digest': 'sha256:' + layer_digest}]}).encode()
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        with tarfile.open(path, 'w:gz') as archive:
            add(archive, 'manifest.json', json.dumps([{'Config': 'blobs/sha256/' + config_digest,
                                                       'Layers': ['blobs/sha256/' + layer_digest]}]).encode())
            add(archive, 'blobs/sha256/' + config_digest, config_bytes)
            add(archive, 'blobs/sha256/' + manifest_digest, manifest)
            add(archive, 'blobs/sha256/' + layer_digest,
                b'bad bytes' if corrupt else gzip.compress(layer_bytes) if compressed else layer_bytes)
        return config_digest, manifest_digest

    def test_docker_save_graph_binds_legacy_config_and_containerd_manifest_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.oci.tar.gz'
            config, manifest = self.archive_fixture(path)
            identity = REFRESH.archive_identity(path)
            self.assertEqual(identity['imageId'], 'sha256:' + config)
            self.assertEqual(identity['platformManifestDigests'], ['sha256:' + manifest])
            self.assertEqual(set(identity['browserFiles']), {'index.html', 'app.css', 'app.js'})

    def test_exported_layer_bytes_must_match_the_preserved_rootfs_diffid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.oci.tar.gz'
            self.archive_fixture(path, corrupt=True)
            with self.assertRaisesRegex(ValueError, 'rootfs DiffID'):
                REFRESH.archive_identity(path)

    def test_compressed_arm_parent_layers_have_the_same_uncompressed_diffid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.oci.tar.gz'
            self.archive_fixture(path, compressed=True)
            identity = REFRESH.archive_identity(path)
            self.assertEqual(set(identity['browserFiles']), {'index.html', 'app.css', 'app.js'})


if __name__ == '__main__':
    unittest.main()
