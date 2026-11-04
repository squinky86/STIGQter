#!/usr/bin/env python3
"""Build only public static files; PHP, caches, backups, and server configuration stay private."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
from urllib.parse import quote
from xml.sax.saxutils import escape
from release_metadata import STABLE_VERSION
from render_docs import render as render_docs

ROOT = Path(__file__).resolve().parents[1]


def build(output, base_url):
    output = output.resolve()
    if output != ROOT / "_site" and output.exists():
        raise ValueError("Custom output directories must not already exist")
    if output != ROOT / "_site" and (output == ROOT or ROOT in output.parents):
        raise ValueError("Use _site or a new output directory outside the source tree")
    web = ROOT / "web"
    release = json.loads((web / "metadata/v1/releases.json").read_text())
    stable = release["stable"]
    if release["schema_version"] != 1 or stable["prerelease"] or not re.fullmatch(STABLE_VERSION, stable["version"]):
        raise ValueError("Invalid stable release metadata")
    if stable["url"] != f"https://github.com/squinky86/STIGQter/releases/tag/{stable['version']}":
        raise ValueError("Unexpected release URL")
    manifest = json.loads((web / "metadata/v1/content.json").read_text())
    catalog_name = manifest["catalog"]["path"]
    if not re.fullmatch(r"catalog-[0-9a-f]{64}\.json", catalog_name):
        raise ValueError("Invalid catalog path")
    catalog = (web / "metadata/v1" / catalog_name).read_bytes()
    if hashlib.sha256(catalog).hexdigest() != manifest["catalog"]["sha256"] or not json.loads(catalog)["stigs"]:
        raise ValueError("Invalid catalog hash or empty catalog")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    # Explicit allowlist; never publish a user project or a PHP program.
    paths = [web / "index.html", web / "404.html", web / "STIGQter.svg", web / "site.css", *web.glob("STIGQter-*.hashes.txt")]
    paths += [path for path in (web / "stigs").rglob("*") if path.suffix.lower() in (".html", ".svg", ".css", ".png", ".jpg")]
    # Keep immutable snapshots available while caches may still serve an older
    # manifest. Their small size is included in the overall publication budget.
    catalogs = sorted((web / "metadata/v1").glob("catalog-*.json"))
    for snapshot in catalogs:
        if snapshot.name != f"catalog-{hashlib.sha256(snapshot.read_bytes()).hexdigest()}.json":
            raise ValueError(f"Invalid immutable catalog: {snapshot.name}")
    paths += [web / "metadata/v1/releases.json", web / "metadata/v1/content.json", *catalogs]
    for source in paths:
        if source.is_symlink():
            raise ValueError(f"Symlinks are not publication inputs: {source}")
        target = output / source.relative_to(web)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if target.suffix == ".html":
            # The historical snapshot embeds obsolete analytics/ads. Preserve
            # content and URLs while removing scripts from the built artifact.
            page = target.read_text()
            page = re.sub(r'<script\b[^>]*>.*?</script>', '', page, flags=re.S | re.I)
            if 'name="viewport"' not in page:
                page = page.replace('</head>', '<meta name="viewport" content="width=device-width, initial-scale=1"></head>')
            page = page.replace('https://www.stigqter.com/', base_url)
            page = page.replace('https://stigqter.com/', base_url)
            target.write_text(page)
    index = (output / "index.html").read_text()
    index = re.sub(r'(<strong>Current Version:</strong>).*?</p>',
                   lambda _: f'<strong>Current Version:</strong> <a href="{escape(stable["url"])}">{stable["version"]}</a></p>', index)
    index = index.replace("</head>", f'<link rel="canonical" href="{escape(base_url)}">\n</head>')
    (output / "index.html").write_text(index)
    render_docs(ROOT.parent, output, base_url)
    urls = [base_url] + [base_url + quote(path.relative_to(output).as_posix(), safe="/")
                        for path in sorted(output.rglob("*.html")) if path.parent != output]
    sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    sitemap += ''.join(f'<url><loc>{escape(url)}</loc></url>\n' for url in urls) + '</urlset>\n'
    (output / "sitemap.xml").write_text(sitemap)
    (output / "robots.txt").write_text(f"Sitemap: {base_url}sitemap.xml\n")
    (output / ".nojekyll").touch()
    total = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
    if total > 250 * 1024 * 1024:
        raise ValueError("Published site exceeds the reviewed 250 MiB budget")
    print(f"Built {sum(path.is_file() for path in output.rglob('*'))} public files, {total:,} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "_site")
    parser.add_argument("--base-url", default="https://squinky86.github.io/STIGQter/")
    args = parser.parse_args()
    if not args.base_url.startswith("https://") or not args.base_url.endswith("/"):
        parser.error("base URL must be HTTPS and end in /")
    build(args.output, args.base_url)
