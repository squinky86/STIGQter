#!/usr/bin/env python3
"""Discover DISA's public compilation and report changes without publishing them.

The default invocation is read-only. Only --notify-report writes GitHub issues.
"""
import argparse
from datetime import date
import hashlib
from http.client import IncompleteRead
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
LISTING_PAGE = "https://www.cyber.mil/stigs/compilations/"
# This is the public query used by the compilation page's cyberDocumentTable.
# It returns all matching records; the page applies pagination in the browser.
LISTING_API = "https://www.cyber.mil/webruntime/api/apex/execute?language=en-US&asGuest=true&htmlEncode=false"
LISTING_QUERY = {
    "namespace": "", "classname": "CyberDocumentController",
    "method": "getCyberDocumentCatalogByDownloadType",
    "params": {"downloadType": "STIG Compilations"},
    "cacheable": False, "isContinuation": False,
}
MAX_JSON = 8 * 1024 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024
CHECK_SECONDS = 600
HEALTH_MARKER = "<!-- stigqter-content-monitor:health -->"


def official_url(url, host):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != host or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.fragment
            or any(char.isspace() or ord(char) < 32 for char in url)):
        raise ValueError(f"Expected a public HTTPS URL on {host}")
    return url


class SameHostRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        official_url(newurl, urlsplit(request.full_url).hostname)
        # Authenticated API requests must never follow redirects with the token.
        if request.has_header("Authorization"):
            raise ValueError("Refusing an authenticated API redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def open_request(request):
    return build_opener(SameHostRedirect()).open(request, timeout=30)


def retry(operation):
    """Retry transient reads, but never blindly retry an issue creation."""
    for attempt in range(3):
        try:
            return operation()
        except HTTPError as error:
            if error.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                raise
        except (URLError, TimeoutError, ConnectionError, IncompleteRead):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)


def fetch_json(request):
    with open_request(request) as response:
        data = response.read(MAX_JSON + 1)
        if len(data) > MAX_JSON:
            raise ValueError("JSON response exceeds the monitoring limit")
        return json.loads(data)


def discover():
    request = Request(LISTING_API, data=json.dumps(LISTING_QUERY).encode(), headers={
        "Content-Type": "application/json", "User-Agent": "STIGQter-content-monitor",
    })
    return select_compilation(retry(lambda: fetch_json(request)))


def select_compilation(listing):
    records = listing.get("returnValue")
    if not isinstance(records, list):
        raise ValueError("DISA's public compilation listing has an unexpected format")
    candidates = []
    for record in records:
        title = record.get("FileName", "")
        # Select by the publication's title, never by a quarter or ZIP filename.
        # READ ME files and the separate Rev. 4 sunset compilation are excluded.
        words = re.sub(r"[^a-z0-9]+", " ", title.lower()).split()
        if (record.get("Classification") != "Unclassified"
                or not {"srg", "stig", "library", "compilation"}.issubset(words)
                or {"read", "readme", "sunset", "draft"}.intersection(words)):
            continue
        url = official_url(record["DownloadLink"], "dl.dod.cyber.mil")
        if not unquote(urlsplit(url).path).lower().endswith(".zip"):
            raise ValueError("DISA's public compilation is not a ZIP link")
        uploaded = date.fromisoformat(record["UploadDate"]).isoformat()
        candidates.append({"title": title, "uploaded": uploaded, "url": url})
    if not candidates:
        raise ValueError("No public SRG-STIG library compilation found in DISA's listing")
    newest = max(item["uploaded"] for item in candidates)
    latest = {item["url"]: item for item in candidates if item["uploaded"] == newest}
    if len(latest) != 1:
        raise ValueError("DISA lists multiple latest compilations; review the listing manually")
    return next(iter(latest.values()))


def archive_digest(url):
    """Stream every check so same-URL, same-size replacements are detected too."""
    official_url(url, "dl.dod.cyber.mil")
    deadline = time.monotonic() + CHECK_SECONDS

    def download():
        if time.monotonic() > deadline:
            raise ValueError("Compilation download exceeded the monitoring time limit")
        digest = hashlib.sha256()
        size = 0
        tail = b""
        request = Request(url, headers={"User-Agent": "STIGQter-content-monitor", "Accept-Encoding": "identity"})
        with open_request(request) as response:
            if response.status != 200:
                raise ValueError("Expected a complete compilation download (HTTP 200)")
            length = response.headers.get("Content-Length")
            expected = int(length) if length is not None else None
            if expected is not None and not 0 < expected <= MAX_ARCHIVE:
                raise ValueError("Compilation size exceeds the monitoring limit or is empty")
            while True:
                if time.monotonic() > deadline:
                    raise ValueError("Compilation download exceeded the monitoring time limit")
                block = response.read(1024 * 1024)
                if not block:
                    break
                if size == 0 and not block.startswith(b"PK\x03\x04"):
                    raise ValueError("DISA returned a non-ZIP compilation response")
                size += len(block)
                if size > MAX_ARCHIVE:
                    raise ValueError("Compilation size exceeds the monitoring limit")
                digest.update(block)
                # ZIP end record plus the maximum permitted archive comment.
                tail = (tail + block)[-65557:]
            if expected is not None and size != expected:
                raise IncompleteRead(b"", expected - size)
            if size < 22:
                raise ValueError("DISA returned an empty or truncated compilation")
            end = tail.rfind(b"PK\x05\x06")
            while end >= 0:
                if end + 22 <= len(tail) and end + 22 + int.from_bytes(tail[end + 20:end + 22], "little") == len(tail):
                    break
                end = tail.rfind(b"PK\x05\x06", 0, end)
            if end < 0:
                raise ValueError("Compilation is missing its complete ZIP end record")
        return {"sha256": digest.hexdigest(), "size": size}

    return retry(download)


def check(manifest):
    published = manifest["quarterly"]
    official_url(published["url"], "dl.dod.cyber.mil")
    if (manifest["schema_version"] != 1
            or not re.fullmatch(r"[0-9a-f]{64}", published["sha256"])
            or not isinstance(published["size"], int) or not 0 < published["size"] <= MAX_ARCHIVE):
        raise ValueError("Invalid committed content metadata")
    candidate = discover()
    observed = candidate | archive_digest(candidate["url"])
    changed = [field for field in ("url", "sha256", "size") if published[field] != observed[field]]
    return {"status": "update" if changed else "current", "changed": changed,
            "published": published, "observed": observed}


def revision_marker(archive):
    identity = json.dumps([archive["url"], archive["sha256"]]).encode()
    return "<!-- stigqter-content-monitor:revision:" + hashlib.sha256(identity).hexdigest() + " -->"


class GitHubIssues:
    def __init__(self, repository, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not token:
            raise ValueError("Issue reporting requires GITHUB_REPOSITORY and GH_TOKEN")
        self.base = f"https://api.github.com/repos/{repository}/issues"
        self.token = token

    def request(self, method, suffix="", data=None):
        request = Request(self.base + suffix, method=method,
                          data=None if data is None else json.dumps(data).encode(), headers={
                              "Accept": "application/vnd.github+json", "Content-Type": "application/json",
                              "Authorization": "Bearer " + self.token, "X-GitHub-Api-Version": "2022-11-28",
                              "User-Agent": "STIGQter-content-monitor",
                          })
        return retry(lambda: fetch_json(request)) if method == "GET" else fetch_json(request)

    def all(self):
        issues = []
        # Enumerate open AND closed issues, without search-index delays. Refuse
        # to create anything if enumeration fails or cannot finish within bounds.
        for page in range(1, 101):
            batch = self.request("GET", f"?state=all&per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ValueError("Unexpected GitHub issue-list response")
            issues.extend(issue for issue in batch if "pull_request" not in issue)
            if len(batch) < 100:
                return issues
        raise ValueError("Issue enumeration exceeded the monitoring limit")

    def create(self, title, body):
        return self.request("POST", data={"title": title, "body": body})

    def update(self, issue, **fields):
        return self.request("PATCH", f"/{issue['number']}", fields)


def report_issues(report, client, repository):
    issues = client.all()

    def find(marker):
        return next((issue for issue in issues
                     if issue.get("user", {}).get("login") == "github-actions[bot]"
                     and (issue.get("body") or "").startswith(marker + "\n")), None)

    def close(issue):
        if issue and issue["state"] == "open":
            client.update(issue, state="closed", state_reason="completed")

    health = find(HEALTH_MARKER)
    workflow = f"https://github.com/{repository}/actions/workflows/content-monitor.yml"
    if report["status"] == "error":
        title = "STIG compilation monitoring failed"
        body = (HEALTH_MARKER + "\nThe daily content check could not determine whether our metadata is current.\n\n"
                + "Diagnostic:\n\n```json\n" + json.dumps(report["error"], ensure_ascii=True) + "\n```\n\n"
                + f"Inspect the [workflow logs]({workflow}) and [DISA's public listing]({LISTING_PAGE}). "
                + "A successful content check will close this issue automatically.\n")
        if health:
            fields = {}
            if health["state"] == "closed":
                fields.update(state="open", state_reason="reopened")
            if health.get("body") != body:
                fields["body"] = body
            if fields:
                client.update(health, **fields)
        else:
            client.create(title, body)
        return

    observed = report["observed"]
    marker = revision_marker(observed)
    existing = find(marker)
    if report["status"] == "update":
        # Respect a maintainer's dismissal. A changed URL or digest gets its own
        # issue; repeated checks of the same revision cause no writes or comments.
        if not existing:
            title = f"Review DISA STIG compilation: {observed['uploaded']} ({observed['sha256'][:12]})"
            body = (marker + "\nDISA's public compilation differs from `site/web/metadata/v1/content.json`.\n\n"
                    + f"Source: [SRG and STIG Library Compilations]({LISTING_PAGE})\n\n"
                    + "Changed fields: " + ", ".join(report["changed"]) + ".\n\n"
                    + "Committed metadata:\n\n```json\n" + json.dumps(report["published"], indent=2) + "\n```\n\n"
                    + "Observed compilation:\n\n```json\n" + json.dumps(observed, indent=2) + "\n```\n\n"
                    + f"Follow the [content refresh procedure](https://github.com/{repository}/blob/main/site/README.md#content-refresh): "
                    + "review the ZIP, regenerate the catalog and library pages, validate, and submit the update for review. "
                    + "The monitor has not changed or published any content.\n\n"
                    + "This issue closes automatically when committed metadata matches this compilation. "
                    + "Closing it manually suppresses further issues for this URL and SHA-256.\n")
            client.create(title, body)
    elif report["status"] != "current":
        raise ValueError("Unexpected content report status")
    # A reviewed revision can be accepted while DISA already lists a newer one.
    # Do not close a same-revision issue if the committed size is still wrong.
    accepted = revision_marker(report["published"])
    if report["status"] == "current" or accepted != marker:
        close(find(accepted))
    # Do this only after the content issue was successfully handled.
    close(health)


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "web/metadata/v1/content.json")
    parser.add_argument("--report", type=Path, help="Write the read-only check result as JSON")
    parser.add_argument("--notify-report", type=Path, help="Create/update GitHub issues from an existing report")
    args = parser.parse_args()
    if args.notify_report:
        report = {"status": "error", "error": "The content check did not produce a readable report; inspect the workflow logs."}
        try:
            report = json.loads(args.notify_report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        report_issues(report, GitHubIssues(repository, os.environ.get("GH_TOKEN", "")), repository)
        print("GitHub issues reconciled with content check: " + report["status"])
        return 0

    report = {"status": "error", "error": "The content check did not finish; inspect the workflow logs."}
    if args.report:
        write_report(args.report, report)
    try:
        report = check(json.loads(args.manifest.read_text(encoding="utf-8")))
    except Exception as error:
        report = {"status": "error", "error": f"{type(error).__name__}: {error}"}
    if args.report:
        write_report(args.report, report)
    print(json.dumps(report, indent=2))
    return 1 if report["status"] == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
