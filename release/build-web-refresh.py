#!/usr/bin/env python3
"""Prepare unsigned 0.9.88 native releases from exact signed 0.9.87 parents.

This refresh changes version metadata only. It never recompiles, modifies,
signs, or publishes the inherited protected runtime or browser filesystem.
"""
import argparse
import copy
import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile


ROOT = Path(__file__).resolve().parent
SOURCE_REVISION = '07a36c699b9da74614b4fa7e5abfebef9e5f6ced'
PARENTS = {
    'main': {'version': '0.9.87', 'target': '0.9.88', 'images': {
        'amd64': '17a1eae4c224b236c299c14620383b6908b05151489d5577a3f5edfca07a276a',
        'arm64': '5fde8cd29ec78e4079bad491a61c9112fe049ad407aa8fb9ea189ba33b98f191'}},
    'dev': {'version': '0.9.87-dev', 'target': '0.9.88-dev', 'images': {
        'amd64': '0aea8c16cf99d01dee0a5ff9f5b5b5b873f3efd4a56ae7f0cbc87e3b47750d48',
        'arm64': '4de0590bbd3c6f8252f7e0df06f950f2c4342ec6bf7ec355f7a16791e7c50632'}},
}


def digest_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def json_write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=300, **kwargs)


def checked_parent(directory, channel):
    expected = PARENTS[channel]
    directory = Path(directory)
    manifest = directory / '5tratmux-release.json'
    signature = directory / '5tratmux-release.json.sig'
    run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
         str(ROOT / 'update-signing-public.pem'), '-rawin', '-in', str(manifest),
         '-sigfile', str(signature)], stdout=subprocess.DEVNULL)
    value = json.loads(manifest.read_bytes())
    if (value.get('schema') != 1 or value.get('product') != '5tratMux'
            or value.get('version') != expected['version'] or value.get('channel') != 'MAIN'
            or set(value.get('images') or {}) != {'amd64', 'arm64'}):
        raise ValueError('The signed parent manifest is not the exact expected native release.')
    for arch, digest in expected['images'].items():
        name = f"5tratmux-{expected['version']}-{arch}.oci.tar.gz"
        image = value['images'][arch]
        if (image.get('sha256') != digest
                or image.get('image') != f"5tratmux:{expected['version']}-{arch}"
                or digest_file(directory / name) != digest):
            raise ValueError(f'The {channel}/{arch} parent does not match its mandatory archive pin.')
    return value


def archive_identity(path):
    """Validate Docker-save graph and hash inherited native/browser content."""
    with tarfile.open(path, 'r:gz') as archive:
        manifests = json.load(archive.extractfile('manifest.json'))
        if len(manifests) != 1:
            raise ValueError('Expected a single-platform Docker-save archive.')
        manifest = manifests[0]
        config_bytes = archive.extractfile(manifest['Config']).read()
        config_digest = hashlib.sha256(config_bytes).hexdigest()
        if not manifest['Config'].endswith('/' + config_digest) and manifest['Config'] != config_digest + '.json':
            raise ValueError('The archive config filename does not match its digest.')
        config = json.loads(config_bytes)
        platform_manifests = []
        json_blobs = {}
        for entry in archive.getmembers():
            if not entry.isfile() or entry.size > 256 * 1024 or not entry.name.startswith('blobs/sha256/'):
                continue
            raw = archive.extractfile(entry).read()
            try:
                value = json.loads(raw)
            except (UnicodeError, ValueError):
                continue
            blob_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            if not entry.name.endswith('/' + blob_digest.removeprefix('sha256:')):
                raise ValueError('An OCI JSON blob does not match its digest.')
            json_blobs[blob_digest] = value
            if (isinstance(value, dict) and isinstance(value.get('config'), dict)
                    and value['config'].get('digest') == 'sha256:' + config_digest
                    and isinstance(value.get('layers'), list)):
                manifest_digest = hashlib.sha256(raw).hexdigest()
                if not entry.name.endswith('/' + manifest_digest):
                    raise ValueError('An OCI platform manifest does not match its digest.')
                platform_manifests.append('sha256:' + manifest_digest)
        local_indexes = []
        for blob_digest, value in json_blobs.items():
            if not isinstance(value, dict) or not isinstance(value.get('manifests'), list):
                continue
            runtime = []
            valid = True
            for descriptor in value['manifests']:
                annotations = descriptor.get('annotations') or {}
                if annotations.get('vnd.docker.reference.type') == 'attestation-manifest':
                    valid = valid and (annotations.get('vnd.docker.reference.digest') in platform_manifests
                                       and descriptor.get('digest') in json_blobs
                                       and descriptor.get('platform') == {'architecture': 'unknown', 'os': 'unknown'})
                else:
                    runtime.append(descriptor.get('digest'))
            if valid and len(runtime) == 1 and runtime[0] in platform_manifests:
                local_indexes.append(blob_digest)
        layers = manifest['Layers']
        diff_ids = config['rootfs']['diff_ids']
        if len(layers) != len(diff_ids):
            raise ValueError('The layer graph is incomplete.')
        browser = {}
        native = None
        for name, diff_id in zip(layers, diff_ids):
            stream = archive.extractfile(name)
            layer_bytes = stream.read()
            # Retained buildx ARM archives store gzip layer blobs; Docker-save
            # exports may instead store uncompressed tar. DiffIDs always hash
            # the uncompressed layer bytes in either supported representation.
            if layer_bytes.startswith(b'\x1f\x8b'):
                layer_bytes = gzip.decompress(layer_bytes)
            if 'sha256:' + hashlib.sha256(layer_bytes).hexdigest() != diff_id:
                raise ValueError('A layer does not match its rootfs DiffID.')
            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode='r:') as layer:
                for entry in layer:
                    filename = entry.name.removeprefix('./')
                    if entry.isfile() and (filename == 'app/5tratmux' or filename.startswith('app/static/')):
                        digest = hashlib.file_digest(layer.extractfile(entry), 'sha256').hexdigest()
                        if filename == 'app/5tratmux':
                            native = digest
                        else:
                            browser[filename.removeprefix('app/static/')] = digest
        if not native or not {'index.html', 'app.css', 'app.js'}.issubset(browser):
            raise ValueError('The protected native binary or browser assets are missing.')
        return {'imageId': 'sha256:' + config_digest, 'config': config,
                'platformManifestDigests': platform_manifests,
                'localIndexDigests': local_indexes,
                'nativeBinarySha256': native, 'browserFiles': browser,
                'browserManifestSha256': hashlib.sha256(json.dumps(browser, sort_keys=True).encode()).hexdigest()}


def verify_refresh(parent, candidate, version):
    """Allow only version/environment metadata and the declared provenance labels."""
    before, after = parent['config'], candidate['config']
    if before['architecture'] != after['architecture'] or before['os'] != after['os']:
        raise ValueError('Refresh changed the native platform.')
    if before['rootfs'] != after['rootfs']:
        raise ValueError('A metadata refresh must preserve every native/browser rootfs layer.')
    if (parent['nativeBinarySha256'] != candidate['nativeBinarySha256']
            or parent['browserFiles'] != candidate['browserFiles']):
        raise ValueError('A metadata refresh changed protected runtime or browser bytes.')
    expected = copy.deepcopy(before['config'])
    expected['Env'] = [f'APP_VERSION={version}' if item.startswith('APP_VERSION=') else item
                       for item in expected['Env']]
    if f'APP_VERSION={version}' not in expected['Env'] or 'APP_CHANNEL=MAIN' not in expected['Env']:
        raise ValueError('Native parent did not declare its normal version/channel environment.')
    expected['Labels'].update({
        'org.opencontainers.image.version': version,
        'com.5tratumos.metadata-parent-config': parent['imageId'],
        'com.5tratumos.native-source-revision': SOURCE_REVISION,
        'com.5tratumos.release-refresh': 'metadata-only',
    })
    if expected != after['config']:
        raise ValueError('Refresh changed runtime configuration outside its declared metadata.')


def build_channel(directory, channel, output):
    parent_manifest = checked_parent(directory, channel)
    pins = PARENTS[channel]
    version = pins['target']
    output.mkdir(parents=True, exist_ok=False)
    images, records = {}, {}
    for arch in ('amd64', 'arm64'):
        parent_archive = Path(directory) / f"5tratmux-{pins['version']}-{arch}.oci.tar.gz"
        parent = archive_identity(parent_archive)
        parent_image = parent_manifest['images'][arch]['image']
        run(['docker', 'load', '--input', str(parent_archive)])
        inspected = json.loads(run(['docker', 'image', 'inspect', parent_image],
                                   text=True, capture_output=True).stdout)[0]
        actual = inspected['Id']
        if (actual not in [parent['imageId'], *parent['platformManifestDigests'], *parent['localIndexDigests']]
                or inspected['Config'] != parent['config']['config']
                or inspected['Architecture'] != arch
                or inspected['RootFS']['Layers'] != parent['config']['rootfs']['diff_ids']):
            raise ValueError('Docker did not load the exact verified parent config.')
        pinned_tag = f"codex-mux-web-parent:{channel}-{arch}-{actual.removeprefix('sha256:')[:16]}"
        run(['docker', 'image', 'tag', actual, pinned_tag])
        image = f'5tratmux:{version}-{arch}'
        with tempfile.TemporaryDirectory(prefix='mux-web-refresh-') as context:
            shutil.copyfile(ROOT / 'Dockerfile.web-refresh', Path(context) / 'Dockerfile')
            run(['docker', 'build', '--pull=false', '--network=none', '--provenance=false',
                 '--platform', f'linux/{arch}',
                 '--build-arg', f'VERIFIED_PARENT={pinned_tag}', '--build-arg', f'APP_VERSION={version}',
                 '--build-arg', f"PARENT_CONFIG_DIGEST={parent['imageId']}", '--tag', image, context])
        archive = output / f'5tratmux-{version}-{arch}.oci.tar.gz'
        with tempfile.TemporaryFile() as saved:
            run(['docker', 'save', image], stdout=saved)
            saved.seek(0)
            with archive.open('wb') as destination:
                with gzip.GzipFile(filename='', fileobj=destination, mode='wb', compresslevel=1, mtime=0) as compressed:
                    shutil.copyfileobj(saved, compressed)
        candidate = archive_identity(archive)
        verify_refresh(parent, candidate, version)
        candidate_docker_id = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image],
                                  text=True, capture_output=True).stdout.strip()
        if candidate_docker_id not in [candidate['imageId'], *candidate['platformManifestDigests'], *candidate['localIndexDigests']]:
            raise ValueError('The exported archive does not contain the built candidate identity.')
        digest = digest_file(archive)
        archive.with_name(archive.name + '.sha256').write_text(f'{digest}  {archive.name}\n')
        images[arch] = {'image': image, 'sha256': digest,
                        'url': f'https://github.com/WillItMod/5tratMux/releases/download/v{version}/{archive.name}'}
        records[arch] = {'parentArchiveSha256': pins['images'][arch], 'parentImageId': actual,
                         'parentConfigDigest': parent['imageId'],
                         'imageId': candidate_docker_id, 'configDigest': candidate['imageId'], 'archiveSha256': digest,
                         'archiveBytes': archive.stat().st_size,
                         'rootfsDiffIds': candidate['config']['rootfs']['diff_ids'],
                         'nativeBinarySha256': candidate['nativeBinarySha256'],
                         'browserManifestSha256': candidate['browserManifestSha256'],
                         'browserFileCount': len(candidate['browserFiles']),
                         'nativeAndBrowserBytesPreserved': True}
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    json_write(output / '5tratmux-release.unsigned.json', {
        'schema': 1, 'product': '5tratMux', 'channel': 'MAIN', 'version': version,
        'minimumOsVersion': '0.5.9', 'publishedAt': timestamp, 'images': images})
    json_write(output / 'release-provenance.json', {
        'schemaVersion': 1, 'version': version, 'distributionChannel': channel,
        'change': 'Version metadata refresh of the exact signed parent native/browser filesystem.',
        'parentVersion': pins['version'], 'inheritedNativeSourceRevision': SOURCE_REVISION,
        'parentManifestSha256': digest_file(Path(directory) / '5tratmux-release.json'),
        'parentSignatureVerified': True, 'signed': False, 'published': False,
        'builderSha256': digest_file(Path(__file__)),
        'recipeSha256': digest_file(ROOT / 'Dockerfile.web-refresh'), 'images': records})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main-parent', required=True, type=Path)
    parser.add_argument('--dev-parent', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    options = parser.parse_args()
    # Verify both public signatures and all four exact archive pins before any
    # Docker work. No private key is read, created, replaced, or copied.
    checked_parent(options.main_parent, 'main')
    checked_parent(options.dev_parent, 'dev')
    build_channel(options.main_parent, 'main', options.output / 'main')
    build_channel(options.dev_parent, 'dev', options.output / 'dev')
    print(f'Unsigned MAIN and DEV candidates prepared in {options.output}')


if __name__ == '__main__':
    main()
