from pathlib import Path
import tempfile
import unittest

from check_site import check
from render_docs import render


class SiteTests(unittest.TestCase):
    def test_documentation_uses_current_sources_and_resolves_repository_links(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / 'doc').mkdir()
            (project / 'src').mkdir()
            (project / 'src/main.cpp').write_text('// source')
            readme = project / 'README.md'
            readme.write_text('# Install\n\n[Guide](doc/guide.md#assess)\n\n[Source](src/main.cpp)')
            (project / 'doc/guide.md').write_text('# Guide\n\n## Assess\n\n[Install](../README.md)\n\n```bash\nqmake6 STIGQter.pro\n```')
            pages = (('README.md', 'installation.html', 'Install'), ('doc/guide.md', 'guide.html', 'Guide'))
            output = project / 'output'
            render(project, output, 'https://squinky86.github.io/STIGQter/', pages)
            install = (output / 'docs/installation.html').read_text()
            guide = (output / 'docs/guide.html').read_text()
            self.assertIn('href="guide.html#assess"', install)
            self.assertIn('https://github.com/squinky86/STIGQter/blob/main/src/main.cpp', install)
            self.assertIn('href="installation.html"', guide)
            self.assertIn('id="assess"', guide)
            self.assertIn('<code class="language-bash">', guide)
            self.assertIn('https://squinky86.github.io/STIGQter/docs/guide.html', guide)
            readme.write_text('# Updated instructions\n')
            render(project, output, 'https://stigqter.com/', pages)
            install = (output / 'docs/installation.html').read_text()
            self.assertIn('Updated instructions', install)
            self.assertIn('https://stigqter.com/docs/installation.html', install)

    def test_project_prefix_and_domain_root_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'docs').mkdir()
            (root / 'docs/index.html').write_text('<h1>Documentation</h1>')
            for base in ('https://squinky86.github.io/STIGQter/', 'https://stigqter.com/'):
                from urllib.parse import urlsplit
                prefix = urlsplit(base).path
                (root / 'index.html').write_text(f'<a href="{base}docs/">Docs</a><a href="{prefix}docs/index.html">Docs</a>')
                check(root, base)
            (root / 'index.html').write_text('<a href="/docs/">Wrong project prefix</a>')
            with self.assertRaises(ValueError):
                check(root, 'https://squinky86.github.io/STIGQter/')
            (root / 'index.html').write_text('<a href="https://squinky86.github.io/STIGQter/docs/missing.html">Missing</a>')
            with self.assertRaises(ValueError):
                check(root, 'https://squinky86.github.io/STIGQter/')

    def test_documentation_rejects_missing_or_outside_repository_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for link in ('missing.md', '../../outside.md'):
                (root / 'README.md').write_text(f'# Guide\n\n[Broken]({link})')
                with self.assertRaises(ValueError):
                    render(root, root / 'output', 'https://example.com/', (('README.md', 'guide.html', 'Guide'),))
