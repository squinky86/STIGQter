#!/usr/bin/env python3
"""Check the static site's local link graph, including case and URL-encoded filenames."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        self.links.extend(value for key, value in attrs if key in ("href", "src") and value)


def check(root, base_url=None):
    root = root.resolve()
    base = urlsplit(base_url) if base_url else None
    errors = []
    count = 0
    for page in root.rglob("*.html"):
        count += 1
        parser = Links()
        parser.feed(page.read_text())
        for link in parser.links:
            parsed = urlsplit(link)
            if not parsed.path:
                continue
            path = unquote(parsed.path)
            if parsed.scheme or parsed.netloc:
                if not base or parsed.netloc != base.netloc or not path.startswith(base.path):
                    continue
                target = root / path[len(base.path):]
            elif path.startswith('/'):
                prefix = base.path if base else '/'
                if not path.startswith(prefix):
                    errors.append(f"{page.relative_to(root)}: {link} (outside the Pages base path)")
                    continue
                target = root / path[len(prefix):]
            else:
                target = page.parent / path
            target = target.resolve()
            if target.is_dir():
                target = target / 'index.html'
            if root != target and root not in target.parents or not target.exists():
                errors.append(f"{page.relative_to(root)}: {link}")
    if errors:
        raise ValueError(f"{len(errors)} broken local links:\n" + "\n".join(errors[:40]))
    print(f"Checked local links in {count} HTML pages")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--base-url", help="Check absolute links within this deployed Pages base URL")
    args = parser.parse_args()
    check(args.root, args.base_url)
