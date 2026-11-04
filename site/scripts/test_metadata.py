import hashlib
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPRedirectHandler, Request
import zipfile

import content_metadata as content
import release_metadata as release


def fixture(path, count=1, duplicate=False):
    with zipfile.ZipFile(path, 'w') as outer:
        for number in range(count):
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as inner:
                inner.writestr('benchmark.xml', f'<Benchmark id="test{number}"><title>Test {0 if duplicate else number}</title>'
                               '<version>1</version><plain-text id="release-info">Release: 1</plain-text></Benchmark>')
            outer.writestr(f'stig{number}.zip', data.getvalue())


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / 'quarterly.zip'
        self.output = self.root / 'metadata'
        fixture(self.archive)

    def tearDown(self):
        self.temp.cleanup()

    def generate(self):
        content.generate(self.archive, 'https://dl.dod.cyber.mil/test.zip', 'Test fixture', self.output)

    def test_complete_catalog_and_preserved_pointer_on_failure(self):
        self.generate()
        previous = (self.output / 'content.json').read_bytes()
        manifest = json.loads(previous)
        catalog = (self.output / manifest['catalog']['path']).read_bytes()
        self.assertEqual(hashlib.sha256(catalog).hexdigest(), manifest['catalog']['sha256'])
        self.assertEqual(json.loads(catalog)['stigs'][0]['legacy_name'], 'Test 0 version 1 Release: 1')
        for count, duplicate in [(0, False), (2, True)]:
            fixture(self.archive, count, duplicate)
            with self.assertRaises(ValueError): self.generate()
            self.assertEqual((self.output / 'content.json').read_bytes(), previous)
        self.archive.write_bytes(b'broken zip')
        with self.assertRaises(zipfile.BadZipFile): self.generate()
        self.assertEqual((self.output / 'content.json').read_bytes(), previous)

    def test_reduction_and_untrusted_origin(self):
        fixture(self.archive, 10)
        self.generate()
        fixture(self.archive)
        with self.assertRaises(ValueError): self.generate()
        with self.assertRaises(ValueError):
            content.generate(self.archive, 'http://dl.dod.cyber.mil/test.zip', 'Test', self.output)

    def test_stable_release_rejects_draft_prerelease_and_unsigned_assets(self):
        data = {'tag_name': '2.0.0', 'draft': False, 'prerelease': False,
                'html_url': 'https://github.com/squinky86/STIGQter/releases/tag/2.0.0',
                'published_at': '2026-11-03T00:00:00Z', 'assets': []}
        for suffix in ['win64.zip', 'ubuntu26.04-amd64.deb', 'source.tar.gz']:
            name = 'STIGQter-2.0.0-' + suffix
            data['assets'].append({'name': name, 'size': 1, 'digest': 'sha256:' + '0' * 64,
                'browser_download_url': 'https://github.com/squinky86/STIGQter/releases/download/2.0.0/' + name})
        target = self.root / 'releases.json'
        release.generate(data, target)
        original = target.read_bytes()
        for change in [{'draft': True}, {'prerelease': True}, {'tag_name': '2.1.0-rc1'}, {'tag_name': '02.0.0'}, {'tag_name': '２.0.0'}, {'assets': []},
                       {'assets': [{'browser_download_url': 'https://github.com/squinky86/STIGQter/releases/download/2.0.0/test.zip'}]}]:
            with self.assertRaises(ValueError): release.generate(data | change, target)
            self.assertEqual(target.read_bytes(), original)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args): return None


@unittest.skipUnless(shutil.which('php'), 'PHP is required only for the temporary legacy bridge')
class LegacyContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'web').mkdir()
        shutil.copytree(content.ROOT / 'legacy', self.root / 'legacy')
        for name in ['update.php', 'stig.php', 'autostig.php']:
            shutil.copyfile(content.ROOT / 'web' / name, self.root / 'web' / name)
        cache = self.root / '.cache'
        cache.mkdir()
        fixture(cache / 'quarterly.zip')
        output = self.root / 'web/metadata/v1'
        content.generate(cache / 'quarterly.zip', 'https://dl.dod.cyber.mil/test.zip', 'Test', output)
        manifest = json.loads((output / 'content.json').read_text())
        self.archive_hash = manifest['quarterly']['sha256']
        (cache / 'archives').mkdir()
        (cache / 'quarterly.zip').rename(cache / 'archives' / (self.archive_hash + '.zip'))
        (cache / 'archives' / (self.archive_hash + '.sha256')).write_text(self.archive_hash)
        self.entry = json.loads((output / manifest['catalog']['path']).read_text())['stigs'][0]
        (output / 'releases.json').write_text(json.dumps({'schema_version': 1, 'stable': {'version': '1.2.7', 'prerelease': False}, 'supported_versions': ['2.0.0']}))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        self.server = subprocess.Popen(['php', '-S', f'127.0.0.1:{port}', '-t', str(self.root / 'web')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.base = f'http://127.0.0.1:{port}/'
        for _ in range(50):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1): break
            except OSError: time.sleep(.02)

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=5)
        self.temp.cleanup()

    def get(self, path, agent='STIGQter/1.2.7'):
        try:
            response = build_opener(NoRedirect).open(Request(self.base + path, headers={'User-Agent': agent}), timeout=3)
        except HTTPError as error: response = error
        with response: return response.code, response.headers, response.read()

    def test_update_and_quarterly(self):
        for version, expected in [('1.2.7', b'OK'), ('2.0.0', b'OK'), ('1.0.0', b'1.2.7')]:
            status, headers, body = self.get('update.php', 'STIGQter/' + version)
            self.assertEqual((status, body), (200, expected))
            self.assertIn('text/plain', headers['Content-Type'])
        status, headers, _ = self.get('stig.php')
        self.assertEqual((status, headers['Location']), (302, 'https://dl.dod.cyber.mil/test.zip'))

    def test_exact_lookup_download_and_unknown(self):
        status, headers, body = self.get('autostig.php?' + urlencode({'stig': self.entry['legacy_name']}))
        self.assertEqual(status, 200)
        self.assertEqual(body.decode(), 'https://www.stigqter.com/autostig.php?download=' + self.entry['key'])
        status, headers, body = self.get('autostig.php?download=' + self.entry['key'])
        self.assertEqual(status, 200)
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(body)))
        status, headers, _ = self.get('autostig.php?' + urlencode({'fn': self.entry['filename']}))
        self.assertEqual(status, 302)
        self.assertEqual(self.get('autostig.php?stig=unknown')[0], 404)
        (self.root / '.cache/archives' / (self.archive_hash + '.sha256')).write_text('0' * 64)
        self.assertEqual(self.get('autostig.php?download=' + self.entry['key'])[0], 503)
