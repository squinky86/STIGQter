#!/usr/bin/env python3
"""Render the repository's reviewed Markdown documentation into the Pages artifact."""
from html import escape
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import markdown
from markdown.treeprocessors import Treeprocessor


PAGES = (
    ('doc/user-guide.md', 'user-guide.html', 'Using STIGQter'),
    ('README.md', 'installation.html', 'Installation and building'),
    ('CHANGES.md', 'changes.html', 'Release notes'),
    ('SECURITY.md', 'security.html', 'Security policy'),
    ('doc/maintenance.md', 'maintenance.html', 'Maintainer guide'),
    ('site/README.md', 'website.html', 'Website and content publishing'),
    ('doc/overhaul-validation.md', 'validation.html', 'Validation record'),
    ('plan-overhaul.md', 'overhaul.html', 'Overhaul plan'),
)
REPOSITORY = 'https://github.com/squinky86/STIGQter'


class RepositoryLinks(Treeprocessor):
    def __init__(self, md, project, source, destinations):
        super().__init__(md)
        self.project, self.source = project, source
        self.destinations = destinations

    def run(self, root):
        for element in root.iter():
            attribute = 'src' if element.tag == 'img' else 'href'
            link = element.get(attribute)
            if not link:
                continue
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = (self.source.parent / unquote(parsed.path)).resolve()
            if not target.is_relative_to(self.project) or not target.exists():
                raise ValueError(f'Invalid documentation link in {self.source}: {link}')
            if target in self.destinations:
                url = self.destinations[target]
            else:
                kind = 'tree' if target.is_dir() else 'blob'
                url = f'{REPOSITORY}/{kind}/main/' + quote(target.relative_to(self.project).as_posix(), safe='/')
                if element.tag == 'img':
                    url = 'https://raw.githubusercontent.com/squinky86/STIGQter/main/' + quote(target.relative_to(self.project).as_posix(), safe='/')
            destination = urlsplit(url)
            element.set(attribute, urlunsplit(destination._replace(query=parsed.query, fragment=parsed.fragment)))


def page(title, body, base_url, path, source=None):
    base = escape(base_url, quote=True)
    source_link = (f'<p class="source"><a href="{REPOSITORY}/blob/main/{quote(source, safe="/")}">'
                   'View this page’s Markdown source</a></p>') if source else ''
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} — STIGQter</title>
<link rel="stylesheet" href="../site.css">
<link rel="icon" type="image/svg+xml" href="../STIGQter.svg">
<link rel="canonical" href="{base}{escape(path, quote=True)}">
</head><body><a class="skip" href="#content">Skip to content</a>
<header><nav aria-label="Main navigation"><a href="../">STIGQter</a>
<a href="./">Documentation</a><a href="../stigs/main.html">STIG library</a>
<a href="{REPOSITORY}">GitHub</a></nav></header>
<main id="content">{body}{source_link}</main></body></html>
'''


def render(project, output, base_url, pages=PAGES):
    project = project.resolve()
    docs = output / 'docs'
    docs.mkdir(parents=True, exist_ok=True)
    destinations = {(project / source).resolve(): filename for source, filename, _ in pages}
    for source, filename, title in pages:
        path = project / source
        if path.is_symlink() or not path.resolve().is_relative_to(project):
            raise ValueError(f'Documentation sources must stay in the repository: {source}')
        md = markdown.Markdown(extensions=['extra', 'toc'])
        md.treeprocessors.register(RepositoryLinks(md, project, path, destinations), 'repository-links', 0)
        body = md.convert(path.read_text())
        (docs / filename).write_text(page(title, body, base_url, 'docs/' + filename, source))
    items = ''.join(f'<li><a href="{escape(filename)}">{escape(title)}</a></li>' for _, filename, title in pages)
    body = ('<h1>STIGQter documentation</h1><p>Install STIGQter, assess checklists, and maintain your projects.</p>'
            f'<ul>{items}</ul><h2>Design and security documentation</h2>'
            f'<p>The <a href="{REPOSITORY}/tree/main/doc">documentation sources</a> also contain the historical '
            'LaTeX installation guide and security-control documentation.</p>')
    (docs / 'index.html').write_text(page('Documentation', body, base_url, 'docs/'))
