#!/usr/bin/env python3
"""Generate versioned public STIG metadata from a verified quarterly archive.

Run locally, review the resulting diff, then let the website workflow publish it.
This script never reads a STIGQter assessment database.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def json_bytes(data):
    return (json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()


def atomic_write(path, content):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def generate(archive, url, release, output, allow_reduction=False):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "dl.dod.cyber.mil" or parsed.username:
        raise ValueError("The quarterly URL must be an official HTTPS DISA download")
    with archive.open("rb") as stream:
        archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    entries = []
    identities = set()
    with zipfile.ZipFile(archive) as quarterly:
        for member in sorted(quarterly.infolist(), key=lambda item: item.filename):
            if not member.filename.lower().endswith(".zip"):
                continue
            if member.file_size > 128 * 1024 * 1024:
                raise ValueError(f"Oversized nested archive: {member.filename}")
            with zipfile.ZipFile(io.BytesIO(quarterly.read(member))) as stig:
                for xml in stig.infolist():
                    if not xml.filename.lower().endswith(".xml"):
                        continue
                    if xml.file_size > 64 * 1024 * 1024:
                        raise ValueError("Oversized XML")
                    data = stig.read(xml)
                    if b"<!DOCTYPE" in data.upper():
                        raise ValueError("DTD-bearing XML is not a publication input")
                    root = ET.fromstring(data)
                    if root.tag.rsplit("}", 1)[-1] != "Benchmark":
                        continue
                    fields = {}
                    for child in root:
                        tag = child.tag.rsplit("}", 1)[-1]
                        if tag in ("title", "version"):
                            fields[tag] = "".join(child.itertext()).strip()
                        elif tag == "plain-text" and child.get("id") == "release-info":
                            fields["release"] = "".join(child.itertext()).strip()
                    if not all(fields.get(key) for key in ("title", "version", "release")):
                        raise ValueError(f"Incomplete STIG identity: {xml.filename}")
                    identity = (fields["title"], int(fields["version"]), fields["release"])
                    if identity in identities:
                        raise ValueError(f"Ambiguous STIG identity: {identity}")
                    identities.add(identity)
                    key = hashlib.sha256(json_bytes(identity)).hexdigest()
                    entries.append({"title": identity[0], "version": identity[1], "release": identity[2],
                                    "benchmark_id": root.get("id", ""), "filename": Path(xml.filename).name,
                                    "archive_member": member.filename, "url": url, "sha256": archive_hash,
                                    "key": key, "legacy_name": f"{identity[0]} version {identity[1]} {identity[2]}"})
    if not entries:
        raise ValueError("Refusing to publish an empty catalog")
    output.mkdir(parents=True, exist_ok=True)
    previous = output / "content.json"
    if previous.exists() and not allow_reduction:
        old = json.loads(previous.read_text())
        old_catalog = json.loads((output / old["catalog"]["path"]).read_text())
        if len(entries) < len(old_catalog["stigs"]) * 0.9:
            raise ValueError("Catalog shrank by more than 10%; review before using --allow-reduction")
    catalog = json_bytes({"schema_version": 1, "stigs": sorted(entries, key=lambda entry: entry["key"])})
    digest = hashlib.sha256(catalog).hexdigest()
    name = f"catalog-{digest}.json"
    atomic_write(output / name, catalog)
    manifest = {"schema_version": 1, "updated_at": datetime.now(timezone.utc).isoformat(),
                "quarterly": {"url": url, "release": release, "sha256": archive_hash, "size": archive.stat().st_size},
                "catalog": {"path": name, "sha256": digest}}
    atomic_write(previous, json_bytes(manifest))
    print(f"Validated {len(entries)} STIGs; quarterly SHA-256 {archive_hash}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "web/metadata/v1")
    parser.add_argument("--allow-reduction", action="store_true")
    parser.add_argument("--stage-legacy", action="store_true", help="Cache the verified ZIP outside the web root for old clients")
    args = parser.parse_args()
    generate(args.archive, args.url, args.release, args.output, args.allow_reduction)
    if args.stage_legacy:
        digest = json.loads((args.output / "content.json").read_text())["quarterly"]["sha256"]
        target = ROOT / ".cache/archives" / (digest + ".zip")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.archive, target.with_suffix(".tmp"))
        target.with_suffix(".tmp").replace(target)
        with target.open("rb") as stream:
            target.with_suffix(".sha256").write_text(hashlib.file_digest(stream, "sha256").hexdigest() + "\n")
