import copy
import hashlib
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request
import zipfile

import content_monitor as monitor


FIXTURE = Path(__file__).with_name("fixtures") / "disa-compilations.json"
URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_October_2026.zip"


def archive_bytes(payload=b"first version"):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("example.zip", payload)
    return stream.getvalue()


def manifest(data, url=URL):
    return {"schema_version": 1, "quarterly": {"url": url, "release": "October 2026",
            "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}}


class Response(io.BytesIO):
    def __init__(self, data, headers=None, status=200):
        super().__init__(data)
        self.headers = headers if headers is not None else {"Content-Length": str(len(data))}
        self.status = status


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        # Public compilation-page query response captured on 2026-11-07.
        self.listing = json.loads(FIXTURE.read_text())
        self.record = self.listing["returnValue"][-1]

    def test_actual_public_query_and_listing(self):
        with patch.object(monitor, "open_request", return_value=Response(FIXTURE.read_bytes())) as request:
            found = monitor.discover()
        self.assertEqual(found, {"title": "Compilation - SRG-STIG Library", "uploaded": "2026-10-26", "url": URL})
        sent = request.call_args.args[0]
        self.assertEqual(sent.full_url, monitor.LISTING_API)
        self.assertEqual(json.loads(sent.data)["params"], {"downloadType": "STIG Compilations"})
        self.assertFalse(sent.has_header("Authorization"))

    def test_revision_suffixes_off_quarter_and_unexpected_filenames(self):
        for filename in ("U_SRG-STIG_Library_October_2026_v2.zip", "U_SRG-STIG_Library_2026_10v3.zip",
                         "U_SRG-STIG_Library_November_2026.zip", "Reissued_Compilation_2026-11-07.zip"):
            with self.subTest(filename=filename):
                revised = self.record | {"DownloadLink": URL.rsplit("/", 1)[0] + "/" + filename,
                                        "UploadDate": "2026-11-07"}
                listing = {"returnValue": [revised, *self.listing["returnValue"]]}
                self.assertEqual(monitor.select_compilation(listing)["url"], revised["DownloadLink"])

    def test_missing_invalid_or_ambiguous_listing_is_a_failure(self):
        for listing in ({}, {"returnValue": []}, {"returnValue": "login page"},
                        {"returnValue": self.listing["returnValue"][:-1]},
                        {"returnValue": [self.record | {"UploadDate": "invalid"}]},
                        {"returnValue": [self.record, self.record | {"DownloadLink": URL.replace(".zip", "_v2.zip")}]}):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                monitor.select_compilation(listing)

    def test_restricted_sunset_and_readme_do_not_displace_public_compilation(self):
        extras = [self.record | {"Classification": "CUI"},
                  self.record | {"FileName": "Compilation - SRG-STIG Library - READ ME"},
                  self.record | {"FileName": "Sunset Compilation - SRG-STIG Library"},
                  self.record | {"FileName": "Draft Compilation - SRG-STIG Library"}]
        for extra in extras:
            extra.update(DownloadLink="https://restricted.invalid/test.zip", UploadDate="2099-01-01")
        self.assertEqual(monitor.select_compilation({"returnValue": extras + [self.record]})["url"], URL)

    def test_rejects_untrusted_or_non_zip_public_link(self):
        for url in (URL.replace("https:", "http:"), URL.replace("dl.dod.cyber.mil", "example.org"),
                    URL.replace("dl.dod.cyber.mil", "user@dl.dod.cyber.mil"),
                    URL.replace("dl.dod.cyber.mil", "dl.dod.cyber.mil:444"), URL + "#fragment",
                    URL.replace(".zip", ".html")):
            with self.subTest(url=url), self.assertRaises(ValueError):
                monitor.select_compilation({"returnValue": [self.record | {"DownloadLink": url}]})


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.data = archive_bytes()

    def test_current_compilation_and_same_size_same_url_replacement(self):
        original = manifest(self.data)
        revised = archive_bytes(b"other version")
        self.assertEqual(len(self.data), len(revised))
        candidate = {"url": URL, "uploaded": "2026-10-26", "title": "Compilation - SRG-STIG Library"}
        for data, status in ((self.data, "current"), (revised, "update")):
            with self.subTest(status=status), patch.object(monitor, "discover", return_value=candidate), \
                    patch.object(monitor, "open_request", return_value=Response(data)):
                result = monitor.check(original)
            self.assertEqual(result["status"], status)
            self.assertEqual(result["changed"], [] if status == "current" else ["sha256"])

    def test_new_url_with_identical_bytes_still_needs_metadata_review(self):
        candidate = {"url": URL.replace(".zip", "_v2.zip"), "uploaded": "2026-11-07", "title": "Compilation - SRG-STIG Library"}
        with patch.object(monitor, "discover", return_value=candidate), \
                patch.object(monitor, "open_request", return_value=Response(self.data)):
            result = monitor.check(manifest(self.data))
        self.assertEqual(result["changed"], ["url"])
        self.assertEqual(result["status"], "update")

    def test_stream_without_content_length_and_size_bound(self):
        with patch.object(monitor, "open_request", return_value=Response(self.data, headers={})):
            self.assertEqual(monitor.archive_digest(URL)["sha256"], hashlib.sha256(self.data).hexdigest())
        for headers in ({}, {"Content-Length": str(len(self.data))}):
            with self.subTest(headers=headers), patch.object(monitor, "MAX_ARCHIVE", 30), \
                    patch.object(monitor, "open_request", return_value=Response(self.data, headers=headers)), \
                    self.assertRaises(ValueError):
                monitor.archive_digest(URL)

    def test_download_errors_are_never_reported_as_releases(self):
        for data, status in ((b"<html>Temporarily unavailable</html>", 200), (b"PK\x03\x04", 200), (self.data, 206)):
            with self.subTest(data=data, status=status), \
                    patch.object(monitor, "open_request", return_value=Response(data, status=status)), \
                    self.assertRaises(ValueError):
                monitor.archive_digest(URL)
        with patch.object(monitor, "open_request", side_effect=lambda request: Response(self.data, {"Content-Length": "1000"})), \
                patch.object(monitor.time, "sleep"), self.assertRaises(IncompleteRead):
            monitor.archive_digest(URL)

    def test_transient_requests_retry_but_permanent_failures_do_not(self):
        unavailable = HTTPError(URL, 503, "unavailable", {}, None)
        with patch.object(monitor.time, "sleep"), \
                patch.object(monitor, "open_request", side_effect=[unavailable, URLError("reset"), Response(self.data)]) as request:
            self.assertEqual(monitor.archive_digest(URL)["size"], len(self.data))
        self.assertEqual(request.call_count, 3)
        missing = HTTPError(URL, 404, "missing", {}, None)
        with patch.object(monitor, "open_request", side_effect=missing) as request, self.assertRaises(HTTPError):
            monitor.archive_digest(URL)
        self.assertEqual(request.call_count, 1)

    def test_download_time_bound(self):
        with patch.object(monitor.time, "monotonic", side_effect=[0, monitor.CHECK_SECONDS + 1]), \
                patch.object(monitor, "open_request", return_value=Response(self.data)), self.assertRaises(ValueError):
            monitor.archive_digest(URL)

    def test_truncated_response_without_content_length_is_a_failure(self):
        with patch.object(monitor, "open_request", return_value=Response(self.data[:-22], headers={})), \
                self.assertRaisesRegex(ValueError, "ZIP end record"):
            monitor.archive_digest(URL)

    def test_zip_comments_including_end_record_signature_are_supported(self):
        stream = io.BytesIO(self.data)
        with zipfile.ZipFile(stream, "a") as archive:
            archive.comment = b"comment with PK\x05\x06 signature"
        data = stream.getvalue()
        with patch.object(monitor, "open_request", return_value=Response(data)):
            self.assertEqual(monitor.archive_digest(URL)["sha256"], hashlib.sha256(data).hexdigest())

    def test_rejects_insecure_redirects_and_authenticated_redirects(self):
        redirect = monitor.SameHostRedirect()
        for url in ("http://dl.dod.cyber.mil/test.zip", "https://example.org/test.zip"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                redirect.redirect_request(Request(URL), None, 302, "found", {}, url)
        redirected = redirect.redirect_request(Request(URL), None, 302, "found", {}, URL.replace(".zip", "_v2.zip"))
        self.assertEqual(redirected.full_url, URL.replace(".zip", "_v2.zip"))
        request = Request("https://api.github.com/repos/example/repo/issues", headers={"Authorization": "Bearer test"})
        with self.assertRaises(ValueError):
            redirect.redirect_request(request, None, 302, "found", {}, request.full_url)


class FakeIssues:
    def __init__(self):
        self.issues = []
        self.writes = []

    def all(self):
        return copy.deepcopy(self.issues)

    def create(self, title, body):
        issue = {"number": len(self.issues) + 1, "state": "open", "title": title, "body": body,
                 "user": {"login": "github-actions[bot]"}}
        self.issues.append(issue)
        self.writes.append(("create", issue["number"]))
        return issue

    def update(self, issue, **fields):
        self.issues[issue["number"] - 1].update(fields)
        self.writes.append(("update", issue["number"]))


class IssueTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeIssues()
        self.repository = "example/repo"
        self.report = {"status": "update", "changed": ["sha256"],
                       "published": manifest(archive_bytes())["quarterly"],
                       "observed": manifest(archive_bytes(b"other version"))["quarterly"] | {"uploaded": "2026-11-07"}}

    def report_issues(self, report=None):
        monitor.report_issues(report or self.report, self.client, self.repository)

    def test_update_issue_is_created_once_and_contains_review_evidence(self):
        self.report_issues()
        self.report_issues()
        self.assertEqual(self.client.writes, [("create", 1)])
        issue = self.client.issues[0]
        for value in (URL, self.report["published"]["sha256"], self.report["observed"]["sha256"], "#content-refresh"):
            self.assertIn(value, issue["body"])
        self.client.update(issue, state="closed")
        self.report_issues()
        self.assertEqual(len(self.client.writes), 2)
        self.assertEqual(self.client.issues[0]["state"], "closed")

    def test_new_digest_at_same_url_and_new_filename_get_distinct_issues(self):
        self.report_issues()
        self.report["observed"]["sha256"] = "0" * 64
        self.report_issues()
        self.report["observed"]["url"] = URL.replace(".zip", "_v2.zip")
        self.report_issues()
        self.assertEqual(len(self.client.issues), 3)

    def test_human_issue_with_copied_marker_cannot_suppress_a_review(self):
        marker = monitor.revision_marker(self.report["observed"])
        human = self.client.create("Copied log", marker + "\nA pasted report")
        human.update(state="closed", user={"login": "someone-else"})
        self.report_issues()
        self.assertEqual(len(self.client.issues), 2)
        self.assertEqual(self.client.issues[1]["state"], "open")
        human["state"] = "open"
        self.report_issues(self.report | {"status": "current", "changed": [], "published": self.report["observed"]})
        self.assertEqual(human["state"], "open")
        self.assertEqual(self.client.issues[1]["state"], "closed")

    def test_accepted_metadata_closes_only_the_matching_issue(self):
        self.report_issues()
        unrelated = self.client.create("Maintainer issue", "Keep this open")
        current = self.report | {"status": "current", "changed": [], "published": self.report["observed"]}
        self.report_issues(current)
        self.report_issues(current)
        self.assertEqual(self.client.issues[0]["state"], "closed")
        self.assertEqual(unrelated["state"], "open")
        self.assertEqual(len(self.client.writes), 3)

    def test_failure_is_deduplicated_closes_on_recovery_and_reopens_on_recurrence(self):
        failure = {"status": "error", "error": "No compilation found"}
        self.report_issues(failure)
        self.report_issues(failure)
        self.assertEqual(self.client.writes, [("create", 1)])
        self.report_issues()
        self.assertEqual(len(self.client.issues), 2)
        self.assertEqual(self.client.issues[0]["state"], "closed")
        self.report_issues(failure)
        self.assertEqual(self.client.issues[0]["state"], "open")
        self.assertEqual(len(self.client.issues), 2)

    def test_accepted_revision_closes_even_when_a_newer_revision_is_available(self):
        self.report_issues()
        previous = copy.deepcopy(self.report["observed"])
        self.report["observed"]["sha256"] = "0" * 64
        self.report["published"] = previous
        self.report_issues()
        self.assertEqual(len(self.client.issues), 2)
        self.assertEqual([issue["state"] for issue in self.client.issues], ["closed", "open"])

    def test_size_only_metadata_error_stays_open_until_fixed(self):
        self.report["published"] = self.report["observed"] | {"size": 1}
        self.report["changed"] = ["size"]
        self.report_issues()
        self.report_issues()
        self.assertEqual(self.client.issues[0]["state"], "open")
        self.assertEqual(self.client.writes, [("create", 1)])
        self.report_issues(self.report | {"status": "current", "changed": [], "published": self.report["observed"]})
        self.assertEqual(self.client.issues[0]["state"], "closed")

    def test_notification_failure_is_propagated_without_clearing_failure_issue(self):
        self.report_issues({"status": "error", "error": "Network outage"})
        with patch.object(self.client, "create", side_effect=HTTPError("https://api.github.com", 403, "forbidden", {}, None)), \
                self.assertRaises(HTTPError):
            self.report_issues()
        self.assertEqual(self.client.issues[0]["state"], "open")

    def test_issue_pagination_includes_closed_issues_and_skips_pull_requests(self):
        client = monitor.GitHubIssues(self.repository, "test-token")
        with patch.object(client, "request", side_effect=[[{"pull_request": {}}] * 100,
                                                          [{"number": 101, "state": "closed"}]]) as request:
            self.assertEqual(client.all(), [{"number": 101, "state": "closed"}])
        self.assertIn("page=2", request.call_args.args[1])
        self.assertIn("state=all", request.call_args.args[1])

    def test_failed_issue_creation_is_not_retried(self):
        client = monitor.GitHubIssues(self.repository, "test-token")
        with patch.object(monitor, "fetch_json", side_effect=URLError("connection lost")) as request, \
                self.assertRaises(URLError):
            client.create("test", "test")
        self.assertEqual(request.call_count, 1)


class CommandTests(unittest.TestCase):
    def test_local_check_is_read_only_and_records_discovery_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with patch("sys.argv", ["content_monitor.py", "--report", str(report)]), \
                    patch.object(monitor, "discover", side_effect=ValueError("No compilation found")), \
                    patch.object(monitor, "GitHubIssues") as client, patch("builtins.print"):
                self.assertEqual(monitor.main(), 1)
            client.assert_not_called()
            self.assertEqual(json.loads(report.read_text())["status"], "error")
            self.assertIn("No compilation found", report.read_text())

    def test_missing_report_from_interrupted_check_opens_failure_issue(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("sys.argv", ["content_monitor.py", "--notify-report", str(Path(directory) / "missing.json")]), \
                patch.dict("os.environ", {"GITHUB_REPOSITORY": "example/repo", "GH_TOKEN": "test"}), \
                patch.object(monitor, "GitHubIssues", return_value=FakeIssues()) as client, patch("builtins.print"):
            self.assertEqual(monitor.main(), 0)
            self.assertTrue(client.return_value.issues[0]["body"].startswith(monitor.HEALTH_MARKER))


if __name__ == "__main__":
    unittest.main()
