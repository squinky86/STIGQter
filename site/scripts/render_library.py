#!/usr/bin/env python3
"""Render a reviewable public HTML library from the catalog's verified ZIP.

Writes a NEW directory only. Merge approved pages into web/stigs without
deleting historic pages. No database or assessment export is an input.
"""
import argparse
import hashlib
from html import escape
import io
import json
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile
from content_metadata import ROOT


def text(node):
    return ''.join(node.itertext()).strip()


def page(title, body):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>STIGQter: {escape(title)}</title>'
            '<style>body{font:1rem system-ui;max-width:75rem;margin:2rem auto;padding:0 1rem}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere}td,th{text-align:left;padding:.4rem;vertical-align:top}'
            'table{border-collapse:collapse}tr{border-bottom:1px solid #ccc}a:focus{outline:2px solid}</style>'
            '</head><body><nav><a href="../index.html">STIGQter</a> / '
            '<a href="main.html">STIG library</a></nav>' + body + '</body></html>\n')


def render(archive, metadata, output):
    if output.exists():
        raise ValueError('Use a new staging directory; this renderer never removes existing pages')
    manifest = json.loads((metadata / 'content.json').read_text())
    catalog_data = (metadata / manifest['catalog']['path']).read_bytes()
    if hashlib.sha256(catalog_data).hexdigest() != manifest['catalog']['sha256']:
        raise ValueError('Invalid catalog checksum')
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != manifest['quarterly']['sha256']:
            raise ValueError('Archive does not match reviewed metadata')
    output.mkdir(parents=True)
    names = set()
    index = []
    with zipfile.ZipFile(archive) as quarterly:
        for entry in json.loads(catalog_data)['stigs']:
            stem = Path(entry['filename']).stem
            if not re.fullmatch(r'[A-Za-z0-9_. -]+', stem) or stem in names:
                raise ValueError('Ambiguous or unsafe guide filename')
            names.add(stem)
            with zipfile.ZipFile(io.BytesIO(quarterly.read(entry['archive_member']))) as stig:
                matches = [name for name in stig.namelist() if Path(name).name == entry['filename']]
                if len(matches) != 1: raise ValueError('Missing or ambiguous benchmark')
                root = ET.fromstring(stig.read(matches[0]))
            title = f"{entry['title']} — Version {entry['version']}, {entry['release']}"
            index.append((title, stem + '.html'))
            rows = []
            for rule in root.iter():
                if rule.tag.rsplit('}', 1)[-1] != 'Rule': continue
                rule_id = rule.get('id', '')
                if not re.fullmatch(r'[A-Za-z0-9_.-]+', rule_id): raise ValueError('Unsafe rule ID')
                filename = f'{stem}--{rule_id}.html'
                rule_title = next((text(child) for child in rule if child.tag.rsplit('}', 1)[-1] == 'title'), rule_id)
                rows.append(f'<tr><td><a href="{escape(filename, quote=True)}">{escape(rule_id)}</a></td><td>{escape(rule_title)}</td></tr>')
                details = f'<p><a href="{escape(stem, quote=True)}.html">{escape(title)}</a></p><h1>{escape(rule_title)}</h1>'
                details += f'<p>{escape(rule_id)} · Severity: {escape(rule.get("severity", ""))}</p><dl>'
                for child in rule:
                    label = child.tag.rsplit('}', 1)[-1]
                    details += f'<dt><strong>{escape(label)}</strong></dt><dd><pre>{escape(text(child))}</pre></dd>'
                (output / filename).write_text(page(rule_title, details + '</dl>'))
            body = f'<h1>{escape(title)}</h1><table><tr><th>Rule</th><th>Title</th></tr>{"".join(rows)}</table>'
            (output / (stem + '.html')).write_text(page(title, body))
    body = '<h1>Public STIG library</h1><p>Source: ' + escape(manifest['quarterly']['release']) + '</p><ul>'
    body += ''.join(f'<li><a href="{escape(name, quote=True)}">{escape(title)}</a></li>' for title, name in sorted(index))
    (output / 'main.html').write_text(page('STIG library', body + '</ul>'))
    shutil.copyfile(metadata / 'content.json', output / 'provenance.json')
    print(f'Rendered {len(index)} guides in {output}; review before merging with the historical snapshot')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--metadata', type=Path, default=ROOT / 'web/metadata/v1')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    render(args.archive, args.metadata, args.output)
