#!/usr/bin/env python3
"""Bounded public health checks; failure preserves publication inputs."""
import hashlib
import json
import os
from datetime import datetime, timezone
from urllib.parse import urljoin, urlencode
from urllib.request import Request, urlopen


def fetch(url, method="GET", user_agent="STIGQter-monitor"):
    with urlopen(Request(url, method=method, headers={"User-Agent": user_agent}), timeout=30) as response:
        data = response.read(32 * 1024 * 1024 + 1) if method == "GET" else b""
        if len(data) > 32 * 1024 * 1024:
            raise ValueError("Response too large")
        return data


def main():
    base = os.environ.get("SITE_BASE_URL", "https://squinky86.github.io/STIGQter/")
    fetch(base)
    fetch(urljoin(base, "docs/"))
    fetch(urljoin(base, "docs/user-guide.html"))
    release = json.loads(fetch(urljoin(base, "metadata/v1/releases.json")))
    if release["schema_version"] != 1 or release["stable"]["prerelease"]:
        raise ValueError("Invalid stable release")
    fetch(release["stable"]["url"], "HEAD")
    for asset in release["stable"]["assets"]:
        fetch(asset["url"], "HEAD")
    manifest = json.loads(fetch(urljoin(base, "metadata/v1/content.json")))
    catalog = fetch(urljoin(base, "metadata/v1/" + manifest["catalog"]["path"]))
    if hashlib.sha256(catalog).hexdigest() != manifest["catalog"]["sha256"] or not json.loads(catalog)["stigs"]:
        raise ValueError("Invalid catalog")
    age = datetime.now(timezone.utc) - datetime.fromisoformat(manifest["updated_at"])
    if age.days > 120:
        raise ValueError(f"Content metadata has not been reviewed for {age.days} days")
    fetch(manifest["quarterly"]["url"], "HEAD")
    # A new quarterly file is a review signal, never an automatic publication.
    now = datetime.now(timezone.utc)
    quarter = ("January", "April", "July", "October")[(now.month - 1) // 3]
    candidate = f"https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_{quarter}_{now.year}.zip"
    if candidate != manifest["quarterly"]["url"]:
        from urllib.error import HTTPError
        try:
            fetch(candidate, "HEAD")
        except HTTPError as error:
            if error.code != 404: raise
        else:
            raise ValueError(f"A newer quarterly bundle is available for review: {candidate}")
    if os.environ.get("CHECK_LEGACY") == "true":
        old = fetch("https://www.stigqter.com/update.php", user_agent="STIGQter/0.0.0")
        current = fetch("https://www.stigqter.com/update.php", user_agent="STIGQter/" + release["stable"]["version"])
        if old.decode().strip() != release["stable"]["version"] or current.strip() != b"OK":
            raise ValueError("Legacy version-check contract failed")
        fetch("https://www.stigqter.com/stig.php", "HEAD")
        entry = json.loads(catalog)["stigs"][0]
        lookup = fetch("https://www.stigqter.com/autostig.php?" + urlencode({"stig": entry["legacy_name"]})).decode().strip()
        if lookup != "https://www.stigqter.com/autostig.php?download=" + entry["key"]:
            raise ValueError("Legacy exact-STIG lookup failed")
        fetch(lookup, "HEAD")
    print(f"Healthy: stable {release['stable']['version']}, {len(json.loads(catalog)['stigs'])} STIGs, metadata age {age.days} days")


if __name__ == "__main__":
    main()
