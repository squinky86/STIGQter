#!/usr/bin/env python3
"""Refresh stable metadata from a published GitHub release, never a source VERSION file."""
import argparse
import json
from pathlib import Path
import re
import urllib.request
from content_metadata import atomic_write, json_bytes, ROOT


STABLE_VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"

def generate(data, output):
    version = data.get("tag_name", "")
    expected_url = f"https://github.com/squinky86/STIGQter/releases/tag/{version}"
    if not re.fullmatch(STABLE_VERSION, version) or data.get("draft", True) or data.get("prerelease", True):
        raise ValueError("Only a published stable release can update the stable pointer")
    if data.get("html_url") != expected_url or not data.get("published_at"):
        raise ValueError("Unexpected release identity")
    assets = []
    for asset in data.get("assets", []):
        url = asset["browser_download_url"]
        if not url.startswith(f"https://github.com/squinky86/STIGQter/releases/download/{version}/"):
            raise ValueError("Unexpected release asset URL")
        digest = asset.get("digest", "") or ""
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("A release asset is missing its SHA-256; verify it before publication")
        assets.append({"name": asset["name"], "url": url, "size": asset["size"], "sha256": digest[7:]})
    # The historical 1.2.7 release has source-only downloads. Compatible future
    # releases must publish the packages before their stable pointer moves.
    if version != "1.2.7":
        required = {f"STIGQter-{version}-win64.zip", f"STIGQter-{version}-ubuntu26.04-amd64.deb", f"STIGQter-{version}-source.tar.gz"}
        if not required.issubset({asset["name"] for asset in assets}):
            raise ValueError("Publish the Windows, Ubuntu, and source packages before updating stable metadata")
    supported = json.loads(output.read_text()).get("supported_versions", []) if output.exists() else []
    result = {"schema_version": 1, "stable": {"version": version, "prerelease": False,
              "url": expected_url, "published_at": data["published_at"], "assets": assets},
              "supported_versions": sorted(set(supported + [version]))}
    atomic_write(output, json_bytes(result))
    print(f"Prepared stable metadata for {version}; review before publishing")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Saved GitHub release API response for an offline run")
    parser.add_argument("--output", type=Path, default=ROOT / "web/metadata/v1/releases.json")
    args = parser.parse_args()
    if args.input:
        data = json.loads(args.input.read_text())
    else:
        request = urllib.request.Request("https://api.github.com/repos/squinky86/STIGQter/releases/latest",
                                         headers={"User-Agent": "STIGQter-site", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
    generate(data, args.output)
