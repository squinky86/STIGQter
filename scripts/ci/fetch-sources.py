#!/usr/bin/env python3
"""Fetch the reviewed Windows toolchain inputs, verifying every SHA-256."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    sources = json.loads(Path(__file__).with_name("sources.json").read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    for name, source in sources.items():
        target = args.output / source["filename"]
        if target.exists():
            with target.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() == source["sha256"]:
                    continue
        temporary = target.with_suffix(target.suffix + ".part")
        try:
            request = urllib.request.Request(source["url"], headers={"User-Agent": "STIGQter-build"})
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
                if not response.url.startswith("https://"):
                    raise ValueError("Source redirected away from HTTPS")
                while block := response.read(1024 * 1024):
                    output.write(block)
            with temporary.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != source["sha256"]:
                raise ValueError(f"{name}: SHA-256 mismatch")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        print(f"Verified {name} {source['version']}")


if __name__ == "__main__":
    main()
