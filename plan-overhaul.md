**STIGQter overhaul plan — publication handoff, 3 November 2026**

**Implementation status:** The overhaul is published to `main`, and the [GitHub Pages preview](https://squinky86.github.io/stigqter.com/) is live from the separate [website repository](https://github.com/squinky86/stigqter.com). The implementation includes shared qmake configuration, production/test separation, bounded networking, GitHub Pages stable/content contracts, worker cleanup, persistence/parser/serializer boundaries, transactional XCCDF/remapping, indexed checklist upgrades, and consolidated Ubuntu 26.04 workflows with a pinned static Qt 6.12 Windows build. The website includes the static artifact builder, legacy compatibility endpoints, generators, tests, monitor, and deployment runbook. See [maintenance instructions](doc/maintenance.md), [validation evidence](doc/overhaul-validation.md), and the [website handoff](https://github.com/squinky86/stigqter.com/blob/main/README.md). A stable desktop release, DNS changes, live-server inventory, native Windows acceptance, and bridge retirement remain separate steps. The observations below record the original planning baseline; they are not claims about the final implementation's test status.

Move the public website to GitHub Pages in stages, publish a desktop release that no longer depends on PHP, and simplify the application through small changes protected by regression tests. Preserve the existing Qt 6/C++17/qmake architecture, database location, checklist formats, and assessment workflow. Make operational continuity the prerequisite for retiring infrastructure.

Publication to `main` and the Pages preview is complete. A stable desktop release, DNS cutover, production legacy-host changes, and hosting retirement remain separate steps. Application work belongs in `/mnt/win/projects/STIGQter`. Website work belongs in `/mnt/win/projects/websites/stigqter.com` and its dedicated Git repository; validate and publish it from that workspace through its own workflow.

The recommended order is: establish a baseline → prepare static metadata and legacy compatibility → ship and validate the compatible desktop release → move the public site → complete the larger internal refactors → retire legacy hosting when its support obligations end. Mechanical cleanup can proceed earlier, but broad database or worker changes should not be bundled with the hosting cutover.

The following observations anchor the plan. Application findings refer to local commit `8d575ca`; website findings refer to the local files unless identified as live checks.

| Observed condition | Consequence for the overhaul |
| --- | --- |
| `VERSION` is `2.0.0`, and `debian/changelog` marks it unreleased. GitHub's latest published release is [1.2.7](https://github.com/squinky86/STIGQter/releases/tag/1.2.7), with no uploaded binary assets. | Keep development version, published version, and supported versions distinct. Do not advertise 2.0.0 as available until its release assets pass validation. |
| Recent [Windows](https://github.com/squinky86/STIGQter/actions/runs/38451276639), [Debian](https://github.com/squinky86/STIGQter/actions/runs/38451276642), [CodeQL](https://github.com/squinky86/STIGQter/actions/runs/41273271610), and [coverage](https://github.com/squinky86/STIGQter/actions/runs/41381132903) runs succeeded. | Preserve working pipelines while adding missing release and regression gates. These successes are historical evidence, not a fresh local test run. |
| `STIGQter.pro` and `tests/tests.pro` duplicate most source, header, form, and resource declarations. | Share qmake configuration while preserving the differences between the application and test targets. |
| `src/dbmanager.cpp` is 3,344 lines; `src/stigqter.cpp` is 1,849; `src/assetview.cpp` is 1,347. UI classes include `RunTests` routines, and `AssetView::ImportXCCDF` parses and updates data directly. | Extract concrete responsibilities and test orchestration before considering larger architectural changes. Line counts identify inspection targets, not acceptance criteria. |
| `common.cpp` mixes downloads, archives, classification, formatting, and diagnostics. Its HTTP download path has no explicit timeout or response-status check and buffers the response before writing it. | Harden and isolate networking before relying on new metadata endpoints. A completed HTTP exchange must not imply a successful archive download. |
| The website uses Nginx/PHP for `update.php`, `stig.php`, `autostig.php`, and `sitemap.php`. Desktop clients explicitly call the first three. | Static hosting alone cannot preserve those contracts. |
| `workercklimport.cpp`, including tag 1.2.7, sends `autostig.php?stig=...` and expects a URL in the response body. Local PHP instead looks for `fn`, issues an HTTP redirect, and currently has an empty lookup map. | Treat automatic missing-STIG retrieval as an existing contract defect. Define and test the actual client behavior before replacing it. |
| Local `update.php` accepts 1.2.7 and 2.0.0, but a live request with `User-Agent: STIGQter/2.0.0` returned `1.2.7`. The live quarterly redirect led to the July 2026 DISA archive. | Reconcile deployed and local state. Capture live responses and deployment inputs before cutover; do not assume this directory exactly represents production. Verify the current authoritative quarterly release separately. |
| The local public web tree contains 20,197 files, including 20,173 HTML files, totaling 78,678,008 bytes, approximately 75 MiB. Backups are stored separately. | Preserve the existing STIG library and its URLs. Measure the built artifact and traffic before choosing a publishing strategy. |
| `.gitignore` already exists. Tests already enable `QStandardPaths` test mode and construct a quarterly archive from local fixtures. | Extend these improvements. Do not plan to recreate them or restore a live bulk download to the default regression suite. |

The review included source and workflow inspection, public GitHub release/run metadata, and small read-only HTTP probes. It did not rebuild the application, execute the integration suite, inspect production server configuration or logs, or verify DNS/account administration. The live website responded successfully through the local HTTP probe. An arbitrary auto-STIG lookup returned 404; that alone does not establish the state of every live lookup.

Keep these constraints throughout implementation:

- Preserve `QApplication::applicationName`, the absence of an organization name, the existing `QStandardPaths::AppDataLocation`, and the portable `STIGQter.db` beside the executable. Changing any of these can strand user data.
- Preserve the distinction between the automatically saved working database and an exported `.stigqter` project snapshot, including pending-edit flushing and dirty-state prompts.
- Preserve both classification banners, parsing and ordering, automatic escalation to the highest asset marking, and report markings. Use synthetic fixtures; public website generation must never consume assessment databases or user exports.
- Keep long operations off the GUI thread and SQL connections local to their owning thread. Preserve existing worker signals and `.ui` object names while extracting implementation.
- Preserve CKL, CKLB, XCCDF, CCI/RMF mappings, supplements, checklist upgrades, eMASS, CMRS, POA&M, findings, and HTML behavior. Test observable output before consolidating format-specific code.
- Retain qmake and C++17 for this overhaul. A CMake conversion, QML rewrite, ORM, plugin framework, or wholesale replacement of QObject domain records would add migration work without resolving the immediate problems.

Use the following explicit build targets, incorporating the maintainer's requested Actions simplification and upgrades. GitHub lists [`ubuntu-26.04`](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) as an available runner, and [Qt's release directory](https://download.qt.io/official_releases/qt/6.12/) contains 6.12.0. Pin a tested 6.12 patch release and its source checksums; review applicable upstream QtBase fixes when selecting it.

| Build concern | Required target |
| --- | --- |
| Linux runner images | Explicit `runs-on: ubuntu-26.04` for application CI, static Windows cross-compilation, analysis, release orchestration, and website workflows. Avoid `ubuntu-latest`, which can resolve to a different release. |
| Containers | Remove the general build/coverage `debian:trixie-slim` containers and use the Ubuntu runner directly. Where a container is actually needed for isolation, use `ubuntu:26.04` with a recorded digest. |
| Windows Qt | Upgrade `QT_VERSION` from 6.11.0 to a pinned Qt 6.12.x release, initially 6.12.0 plus applicable reviewed fixes. Build Linux host tools and the static MinGW x64 target from the same source version. Preserve static OpenSSL, SQLite/platform plugins, and PE hardening. |
| Linux Qt and libraries | Use Ubuntu 26.04 development packages for ordinary builds and CodeQL, sharing setup scripts. Remove the separate CodeQL Qt 6.8 installation and ad hoc libxlsxwriter source-package build if the distro packages satisfy tested requirements. The Windows toolchain version does not automatically raise the application's minimum Qt version. |
| Package compatibility | A `.deb` built on Ubuntu 26.04 must be labeled with that baseline. Check dependency resolution and installation on every advertised Debian/Ubuntu target; keep Debian support claims only with evidence or a separately justified compatibility build. |
| Cache identity | Include Ubuntu release, architecture, compiler/toolchain versions, Qt/dependency versions, source/patch digests, and configuration-script hashes. Invalidate the 24.04/6.11 cache; verify both a clean build and a cache reuse build. |

Consolidate the application workflows into `ci.yml` and `release.yml`. `ci.yml` contains Linux build/test/package, static Windows build, CodeQL, and scheduled/manual coverage jobs; `release.yml` calls the same CI builders for an exact tag and publishes their validated outputs. Keep the website's build/deploy workflow in its own repository. Use small checked-in setup/build/verification scripts instead of long duplicated YAML shell blocks or chains of wrapper workflows. CodeQL still requires its own traced compilation; reuse dependency setup rather than pretending an already-built binary can supply analysis.

Run deterministic regression tests on PRs and default-branch pushes. Run expensive coverage publishers from one instrumented test execution on a weekly/manual trigger, reuse its reports, and consolidate duplicate schedules. Keep secrets out of fork PR jobs, scope write permissions to analysis/publication jobs, set timeouts, and cancel superseded PR runs without cancelling releases. Replace the old four workflows only after stable required-check names, badges, artifacts, and the release handoff are updated. Prefer distro packages or a virtual environment for Python verification tools instead of `pip install --user` into Ubuntu's system Python.

The website migration must account for each public contract:

| Existing route or asset | Target behavior | Compatibility requirement |
| --- | --- | --- |
| `/`, `/index.php` | Static `index.html` with installation, downloads, documentation, support, and content links. | Keep bookmarks usable; handle `/index.php` explicitly in the legacy redirect configuration and verify the eventual static alias if retained. |
| `/stigs/main.html`, `/stigs/*.html`, linked images/styles | Preserve existing paths and printable content in the Pages artifact. | Crawl internal links, including rule pages, spaces, case-sensitive filenames, and URL encoding. Do not rename the library during cutover. |
| `/STIGQter-*.hashes.txt`, `/STIGQter.svg` | Preserve historical files and link current checksums from releases. | Historical checksums must continue to describe their original artifacts. |
| `/sitemap.php`, `/robots.txt` | Generate `sitemap.xml` at build time and update robots/canonical URLs. | Redirect the old sitemap on the bridge host; test any static compatibility alias on Pages. |
| `/update.php` | New clients read versioned static release metadata and compare versions locally. | Old clients need a plain `OK` or a published version string based on their User-Agent; an HTML page or unconditional version response is not equivalent. |
| `/stig.php` | New clients resolve the quarterly archive from static content metadata. | Old clients expect an HTTP redirect to a ZIP. Returning JSON or an HTML redirect page will break downloading. |
| `/autostig.php?stig=...` | New clients use a static catalog keyed by exact STIG identity. | Support the released client's plain-URL response contract on the bridge. Inventory whether other callers use `fn`; preserve that variant separately if needed. Unknown identities must fail clearly. |

GitHub Pages publishes static files and does not provide a PHP runtime. Copying PHP source into the artifact, using a JavaScript redirect, or adding a custom 404 page cannot reproduce these desktop HTTP contracts. See [GitHub's Pages overview](https://docs.github.com/en/pages/getting-started-with-github-pages/about-github-pages).

The recommended transition uses `https://stigqter.com` as the canonical Pages website while temporarily keeping `www.stigqter.com` on the existing host. Exact matches for the three desktop endpoints continue working there; ordinary browser paths redirect to the same path on the apex site. Also handle the old index and sitemap paths explicitly. Inventory other consumers before narrowing those rules. This works with the observed desktop URLs and avoids adding a new hosting provider just for migration.

This bridge keeps a small server responsibility during the transition. A new `api.stigqter.com` hostname alone cannot help binaries that hard-code `www.stigqter.com`. If immediate retirement of the old server becomes a requirement, first replace the bridge with a separately tested HTTP routing service at the same legacy hostname. That alternative still has operational ownership and cost. Moving both hostnames directly to Pages requires an explicit end to support for endpoint-dependent clients; it cannot promise uninterrupted downloads for those binaries.

The new clients should consume these proposed static contracts. Use an explicit schema version and immutable content snapshots so schema changes and partial updates cannot silently change their meaning.

| Proposed resource | Contents and behavior |
| --- | --- |
| `/metadata/v1/releases.json` | Latest published stable version, release page, platform asset URLs and SHA-256 values, and supported/minimum-version information where needed. Publish after assets exist and have been checked. Development builds newer than stable must not receive a downgrade prompt. |
| `/metadata/v1/content.json` | Current validated quarterly archive URL, upstream release/date, retrieval time, size/hash when verified, and the path/hash of an immutable catalog snapshot. |
| `/metadata/v1/catalog-<digest>.json` | STIG title, version, release, benchmark ID, XCCDF filename, source archive URL, and provenance. Preserve exact identities and explicitly defined aliases; never silently substitute a newer STIG when importing an older checklist. |

Resolve the known built-in `www.stigqter.com/stig.php` setting through the new metadata service at runtime. Preserve user-supplied quarterly URLs and `file://` sources, including those loaded from older project snapshots. This avoids a database migration solely for a hosting URL. If a persisted setting or schema change proves necessary, add a versioned migration through `UpdateDatabaseFromVersion`, currently at schema version 10, and test both fresh and upgraded databases.

Cache only validated metadata, retain the last usable catalog after refresh failure, show its age, and keep manual ZIP/checklist import available. Separate “unable to check” from “up to date.” Reject malformed schemas and unusable URLs; keep TLS verification enabled. Scope any approved remote-host policy to automatically supplied catalog URLs without removing explicit local/custom import support. Do not require desktop GitHub credentials or a runtime GitHub API call. A public repository copy of validated metadata can be a documented fallback if testing shows it is needed.

Implement the work in the following sequence. Each numbered item should produce independently reviewable changes and its own validation evidence.

1. **Capture the baseline and make regression results a merge gate.** Application maintainer owns this step; the website maintainer supplies the hosting inventory.

   Record the commit, Qt/compiler/library versions, current release assets, clean-build results, test results, and representative import/export timings. Capture fresh-schema and older saved-project fixtures using synthetic assessments. Record counts, mappings, comments, severity overrides, markings, and project hashes where meaningful.

   Consolidate the existing workflows into the CI/release structure above and move Linux jobs to Ubuntu 26.04. Add a fast application/test job on pull requests and pushes. Keep the fixture-based quarterly test; separate any live DISA checks into an optional or scheduled job. The current coverage job is scheduled/manual, so a successful weekly run is insufficient protection for each refactor. Preserve CodeQL and Windows static-linkage/hardening checks.

   Make test isolation explicit and unique per run. Existing Qt test mode is useful but uses a predictable location, and a portable database beside the test executable takes precedence over application-data paths. Use a disposable checkout/build and isolated user/test paths; refuse to run if an unexpected portable database would be touched. Give waits bounded timeouts and ensure test outputs cannot collide across runs. Keep fixture-dependent execution rooted at the repository root.

   Website inventory must include the deployed document root, effective routes, cron/systemd jobs, source of the STIG HTML generator, certificate renewal, DNS records/TTL, domain ownership, and recent endpoint usage if logs are available. Store backups securely outside public repositories and reconcile differences with the local directory. Do not copy logs, server secrets, or `backups/` into the new website repository.

   Exit when the existing application passes its baseline, tests cannot touch a maintainer's working database, and every website route/job has an owner and disposition. Record existing failures separately rather than accepting new ones as baseline noise.

2. **Build the static publication inputs and repair legacy contracts.** Website maintainer owns the site/catalog; application maintainer owns the consumer contract and fixtures.

   Create or select a dedicated website repository, provisionally `squinky86/stigqter.com`, subject to account/repository confirmation. Keep it separate from the desktop repository and its release pipeline. Start with plain HTML/CSS, public assets, and small generation scripts; a JavaScript application framework is unnecessary for this site.

   Preserve the current public STIG snapshot as a verified migration input. Identify how to regenerate it from public DISA content and record source versions/checksums. Keep large historical snapshots and binaries out of growing Git history; use versioned release assets or another documented immutable input store if needed. A clean build must reproduce the selected snapshot without depending on files left on the old server. Do not make routine page deployment depend on downloading the entire live quarterly library.

   Replace `sitemap.php` with generated XML and make `index.php` static. Preserve useful support, licensing, attribution, and donation links. Review existing analytics, advertising, and quality badges deliberately; default to removing obsolete scripts/badges and retain only integrations with a named purpose and owner. This is also the point to correct download instructions and add a mobile viewport if needed.

   Replace `scripts/hrefs.php`/`updateHrefs.sh` with a validated catalog-generation job. The current script uses an upstream implementation-specific API and disables certificate verification. Fetch with normal TLS checks, validate archive/XML contents, build both filename and exact STIG identity indexes, and compare new entry counts against the previous snapshot. Empty, truncated, duplicate/ambiguous, or unexpectedly reduced catalogs must fail publication and preserve the prior snapshot. Distinguish an unavailable historical STIG from a successful match.

   Generate the legacy endpoint data from the same reviewed metadata. Fix `stig` versus `fn` behavior and test it against the 1.2.7 client protocol. Keep quarterly redirects as HTTP redirects and update responses as plain text. Do not publish a newer version number before its assets are ready. Use contract fixtures for supported, old, and unknown User-Agents; known and unknown STIG identities; and both lookup variants if retained.

   Exit when a static site artifact, release/content schemas, valid catalog, and legacy route configuration can be reviewed together, with tests demonstrating their response bodies and redirect behavior.

3. **Ship the desktop compatibility release and establish durable downloads.** Application maintainer owns code and release artifacts; website maintainer updates public metadata after publication.

   Extract a small download component from `common.cpp`, initially keeping adapters for existing callers. Add explicit total/transfer deadlines, HTTP and network error checks, redirect handling, bounded metadata responses, streamed archive writes, checked writes, and cleanup of partial files. Preserve `file://` behavior and the caller's open/closed file state. Return structured outcomes so workers can distinguish success, cancellation, and failure. Keep network work in worker threads.

   Update `WorkerCheckVersion`, `WorkerSTIGDownload`, and missing-STIG handling in `WorkerCKLImport` to use the static contracts. The version check must target the new GitHub Pages site's `/metadata/v1/releases.json`, initially `https://squinky86.github.io/stigqter.com/metadata/v1/releases.json`, rather than `update.php`. Compare application versions numerically against the published stable release; ignore prereleases and never prompt a newer development build to downgrade. Validate archive contents before import, propagate failures from nested workers, and avoid reporting “Done” after a failed or empty download. Test offline startup, metadata failure, a missing historical STIG, and manual import recovery.

   Add release automation for an explicit tag whose version matches `VERSION`. Build the exact tagged revision and attach Windows portable ZIP/executable, Debian package, source, checksums, release notes, and dependency/license information to GitHub Releases. CI artifacts remain useful for testing; the public installation path must not depend on their expiration or a user's GitHub login.

   Resolve packaging discrepancies: the NSIS script is not built by the current Windows workflow and expects `doc/UsersGuide.pdf`, which is not tracked. Either generate and test the installer/manual or clearly advertise portable Windows distribution for this release. Update or explicitly retire stale Gentoo recipes. Upgrade both host and target Qt to 6.12 for the static Windows build on Ubuntu 26.04, and align the README's minimum with the tested Linux package baseline. Cross-compilation success alone does not prove Windows startup or TLS/SQLite operation.

   Check downloaded dependency archives against recorded digests, retain pinned action revisions and existing hardening verification, and test packaging on clean Windows/Linux environments. Fix Debian's source archive command to use the checked-out revision instead of unconditionally archiving `master`, so PR/tag builds describe their actual source. Update `SECURITY.md` and installation/support claims to match what is actually shipped.

   The tentative release is 2.0.0 because it is still unpublished in the observed repository. Recheck releases before implementation and choose the next version if that has changed. Publish a candidate first; exercise save/load and old-project upgrades before promoting it. Update the website's stable pointer only after anonymous asset downloads, hashes, and smoke tests pass.

   Exit when a user can download the new version, preserve existing assessments, import content and export reports offline, and use online operations without any PHP dependency. Keep legacy endpoints available for users who have not upgraded.

4. **Deploy Pages and cut over the public website.** Website agent/maintainer owns implementation, publication, DNS, and rollback; application maintainer supplies desktop compatibility results.

   Add separate site build/validation and deploy jobs on `ubuntu-26.04` using `configure-pages`, `upload-pages-artifact`, and `deploy-pages`, pinned to reviewed revisions. Give the deploy job the required `pages: write` and `id-token: write` permissions, restrict deployment branches through the `github-pages` environment, and serialize deployments. PRs validate artifacts without replacing production. See [GitHub's custom workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

   Test the site at its repository Pages URL before assigning the production domain. Make asset and internal URLs work under the preview repository prefix and the final domain root. Check the entire internal link graph, representative historical STIG/rule links, XML, JSON, release downloads, browser/mobile layouts, and the custom 404 page. Keep PHP programs and private inputs out of the published artifact.

   The measured current content fits within Pages' published-site limit, but add a conservative artifact-size budget, such as 250 MiB initially, and inspect traffic before cutover. GitHub currently documents a 1 GB published-site limit, a soft 100 GB/month bandwidth limit, and a 10-minute deployment timeout. Store installers and quarterly ZIPs outside Pages and measure growth during each refresh. See [GitHub Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits).

   Before changing DNS, export the existing zone, identify unrelated MX/TXT/subdomain records, lower only relevant TTLs sufficiently in advance, and verify domain ownership through GitHub's TXT procedure. Configure `stigqter.com` in the website repository's Pages settings before directing traffic there. With a custom Actions workflow, the Pages setting is authoritative; a `CNAME` file is not required. See [domain verification](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages) and [custom-domain configuration](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site).

   Point only the apex web records to Pages using GitHub's then-current DNS instructions; remove conflicting apex records and check both IPv4 and IPv6. Keep `www` resolving to the compatibility host during this stage, with a valid certificate and exact endpoint routing. Test certificate issuance and HTTPS enforcement as part of the cutover window; restore the old route if TLS cannot be made healthy. Keep mail and other services unchanged. Pages' normal automatic apex/www redirection applies only after both hostnames use the appropriate Pages DNS configuration.

   Immediately check public pages, legacy endpoints with real client User-Agents, quarterly redirect/download validity, known auto-STIG results, and new static metadata from outside the hosting environment. Verify that browser redirects have no loops. Keep the old web snapshot, host, and certificate usable for at least 30 days and one successful content refresh; retain legacy routes longer if the support window requires it.

   Roll back a defective site artifact by redeploying the last validated artifact. For DNS/TLS failures, restore recorded apex records and the old site configuration. Account for DNS caches by keeping both hosts and compatible metadata available during propagation. A failed legacy endpoint is a cutover failure even if the home page looks correct.

   Exit when the public site is served by Pages, legacy and new clients pass the agreed checks, monitoring is active, and rollback has been rehearsed. This milestone does not itself authorize retirement of the compatibility host.

5. **Simplify build configuration and remove test orchestration from production classes.** Application maintainer owns these small, primarily mechanical changes.

   Introduce a shared qmake `.pri` file for the common sources/headers/forms/dependencies. Keep `STIGQter.pro` as the application entry point and authority, with `main.cpp` only in the app and Qt Test only in the test target. Preserve `/dod` resource aliases; the current test resource set differs from the application's and must be checked explicitly. Rebuild both targets and the Windows cross-build after changing source declarations.

   Move `STIGQter::RunTests*`, `AssetView::RunTests`, related tab test routines, and test-only event pumping into test helpers. Drive existing stable slots and widget object names or expose narrow useful interfaces; do not add a large production testing API. Preserve the current scenario assertions and per-test watchdog boundaries. Replace unbounded polling with bounded completion checks using Qt's test facilities.

   Put coverage flags and platform-specific link configuration into explicit qmake options/scripts rather than editing generated Makefiles or splicing the project file in workflows. Handle the current Windows library-order workaround only after verifying whether the supported toolchain still requires it. Keep any necessary workaround documented and covered by the Windows build.

   Exit when source lists are declared once, test scenarios live under `tests/`, both target resources resolve correctly, and resulting behavior remains unchanged. Keep existing `.gitignore` rules; add omissions only when new artifacts justify them.

6. **Extract application responsibilities one vertical workflow at a time.** Application maintainer owns the code; reviewers assess each extraction against the baseline.

   Start with the download component already introduced for compatibility. Separate archive helpers and classification conversions from `common.cpp` without changing their public behavior. Centralize shared marking decisions while retaining display-specific rendering in the UI and each report writer. Avoid changing classification parsing and moving files in the same patch.

   Consolidate worker/thread ownership in one small coordinator behind the current `ConnectThreads` entry points. Make completion and error outcomes explicit, ensure cleanup happens once, and release thread-local SQL resources in the correct lifecycle. Audit list mutation during `CleanThreads`, closing a window during work, nested worker warnings, and busy-state restoration. Keep the current signals as adapters until callers are migrated; do not convert the entire application to futures or a new concurrency framework.

   Move XCCDF result parsing out of `AssetView::ImportXCCDF` into a parser plus a worker that applies validated results. Keep file selection and widget updates on the GUI thread. Move checklist edit/flush logic behind a small assessment service only where it reduces duplicated selection/filter/export handling. Preserve autosave, severity justification, multi-selection, keyboard navigation, and next-not-reviewed behavior.

   Split persistence implementation behind the existing `DbManager` facade: connection lifecycle and migrations; project validation/save/load; and catalog/assessment queries. Prefer internal helpers or separate implementation files before introducing new public repository interfaces. Preserve SQL semantics during the initial split. Subsequently add scoped transactions with explicit commit/rollback to operations where failure can leave partial data; characterize existing `DelayCommit` and nested-call behavior first.

   Separate CKL/CKLB parsing and serialization from worker orchestration. Reuse genuinely common assessment selection, marking, and spreadsheet-format helpers across report workers, while retaining format-specific field names, column layouts, escaping, and validation. Give archive handles, XML readers, and spreadsheet objects deterministic cleanup where manual ownership is currently fragile.

   Exit after each workflow retains its tests, produces equivalent outputs, and has clearer ownership with less duplicated behavior. Record import duration, peak memory, checklist filtering responsiveness, and query counts on a fixed synthetic workload. Set regression thresholds from the baseline; avoid pursuing arbitrary file-size or class-count targets.

7. **Make routine maintenance repeatable and retire the bridge deliberately.** Application and website maintainers share an operations checklist, with an identified backup owner.

   Schedule a bounded content check and provide a manual refresh command. Produce a reviewable diff when quarterly/catalog inputs change; publish only complete validated snapshots. Reuse cached public archives when possible. Record upstream URLs, archive digests, generation time, catalog count, and previous snapshot so an upstream layout change can be diagnosed and rolled back.

   Keep the bundled CCI and Rev. 5 controls reproducible. Pin the NIST OSCAL input commit/hash when running `scripts/generate_rev5_controls.py`, review mapping differences, and retain local input support. A content refresh must not silently change assessment mappings without a tested migration/import path.

   Monitor the home page, release metadata, catalog, downloadable release assets, and legacy route semantics. Perform a small archive/content validation periodically rather than repeatedly downloading the full quarterly bundle. Monitor metadata freshness and certificate/domain renewal, and surface failed or missed scheduled jobs. Assign someone to review failures; scheduled jobs alone are not an operational handoff.

   Publish a support policy for the new release and legacy clients, including the upgrade path and a bridge retirement date only after an adequate notice period. A reasonable initial proposal is at least 90 days after the compatible release and one quarterly content cycle, extended for supported deployments that still require the endpoints. Traffic alone cannot prove disconnected or infrequent clients have upgraded.

   At retirement, either retain a minimal compatibility service or explicitly end the endpoint-dependent versions' online support. If ending that support, move `www` to Pages, verify canonical redirects/HTTPS, then remove only STIGQter-specific PHP jobs/configuration after the rollback period. Do not remove shared Nginx/PHP/certificate infrastructure used by other websites. Retain domain verification records, secure deployment backups, and documentation of historical contracts.

   Exit when recurring content/release work can be completed from documented commands by a second maintainer, and every remaining service has an owner, failure signal, and recovery procedure.

Use this verification matrix for review and release decisions. Add fixture-based tests when behavior is changed; a mechanical file move should use the existing tests rather than a new suite that merely mirrors the implementation.

| Area | Required evidence |
| --- | --- |
| Builds and packaging | Clean qmake application/test builds on Ubuntu 26.04; Qt 6.12 host/target version checks; cold and warm Windows toolchain-cache builds; `.deb` dependency/install/start checks on advertised targets; Windows portable start, TLS and SQLite smoke tests; static imports and hardening checks; installer install/uninstall if offered. Record the supported toolchain versions. |
| Actions simplification | Two application workflows with shared scripts, no duplicated build definitions in release automation, correct PR/push/tag/schedule/manual behavior, required checks and badges updated, coverage reports from one test run, and explicit Ubuntu 26.04 labels. Validate YAML and scripts locally before later review-authorized GitHub runs. |
| Persistence | Fresh schema and representative prior schemas; portable and normal data paths; valid/invalid/newer project files; failed migration/save recovery; restart with edits intact. Preserve existing atomic project replacement and validation. |
| Classification | Synthetic parsing/order checks; asset escalation; top and bottom banners; report headers/markings after import, load, and editing. Keep normal-environment UI tests within the established UNCLASSIFIED/CUI boundary; exercise other marking policies only under the maintainer's appropriate test procedure. |
| Assessment workflow | Load RMF/CCI → load STIG → create asset → attach/import checklist → assess → save/reopen → export. Include unsaved edits, selection changes, filtering, cancellation, missing data, worker failure, and closing during work. |
| Formats and mappings | CKL and CKLB import/export round trips; multi-STIG CKLs; supplements and XCCDF zip re-import; numeric release upgrade; comments, overrides/justification and CCI/RMF preservation. Compare semantic data where timestamps/ordering vary. |
| Reports | Fixtures for eMASS, CMRS, POA&M and findings columns/values; formulas/escaping; HTML links and markings. Preserve consumer-required layouts. |
| Network and metadata | Local HTTP fixtures for valid redirects, 404/500, timeout, disconnect, malformed/empty/oversized metadata, bad ZIP, checksum mismatch, and older/newer application versions; TLS-failure coverage in a controlled fixture; manual/offline fallback. |
| Legacy compatibility | Actual 1.2.7 and relevant 2.0.0 builds, isolated data, both configured and built-in quarterly URLs; `update.php` plain-text semantics; ZIP redirect; successful and unsuccessful exact auto-STIG lookup. A browser-only test is insufficient. |
| UI | Interactive checks at 800×600 and a large window on supported platforms: labels, tab/toolbox access, focus/shortcuts, disabled/busy states, progress/errors, dialogs, autosave feedback, and both banners. |
| Website | Internal link crawl, historic URLs, static schema validation, artifact size, public-only inputs, preview/final base paths, apex/www routing, HTTPS, anonymous release downloads, metadata freshness, and rehearsed rollback. |

Build commands remain `qmake6 STIGQter.pro` and `make -j"$(nproc)"`, followed by `qmake6 tests.pro` and `make` within `tests/`. Run the test executable from the repository root in the disposable environment. The existing guidance to isolate `XDG_DATA_HOME` remains useful, but verify the effective Qt test path as well; do not assume that one environment variable overrides test mode or the portable-database precedence. No build/test execution is required solely for this planning document.

For any actual schema change, save a verified pre-upgrade backup and prove rollback using a copy of it. Do not assume installing an older executable can read a newly migrated database. Keep database migrations separate from mechanical extraction, increment the schema version through `UpdateDatabaseFromVersion`, and preserve the active database if validation or migration fails. Release rollback consists of restoring a compatible binary **and** the appropriate backup when required, not rewriting users' working databases silently.

The principal failure modes and responses are:

| Failure | Prevention and recovery |
| --- | --- |
| Pages migration breaks old clients | Keep the legacy hostname/routes, test real client contracts, and block cutover on failures. Restore route configuration or DNS if necessary. |
| DISA changes its catalog or an archive disappears | Preserve the last valid metadata, retain source provenance, flag stale/missing entries, and offer manual import. Never publish an empty replacement catalog or guess an incompatible STIG version. |
| Release metadata advertises unavailable files | Publish and verify assets first, then update the stable pointer. Restore the previous pointer without deleting prior releases. |
| Data or marking regression | Stop the release, retain fixtures and failing outputs, revert the behavior change, and recover using verified backups when needed. |
| Refactor destabilizes concurrency or UI | Limit each change to one workflow, retain signal adapters, test cancellation/shutdown/error completion, and revert independently of website changes. |
| Pages growth or bandwidth exceeds expectations | Measure before cutover and on refresh, keep large downloads elsewhere, and adjust content distribution before hitting the documented limits. |
| Maintenance automation stops running | Monitor freshness as well as job success, document a manual refresh, and keep a backup maintainer with the necessary access. |

These decisions should be settled during plan review or the baseline inventory. The defaults below allow implementation to start without turning every refactor into a design debate.

| Decision | Recommended default | What must be confirmed |
| --- | --- | --- |
| Website source location | Dedicated `stigqter.com` repository, managed from the existing website workspace. | GitHub owner, repository availability, website agent instructions, and publish permissions. |
| Canonical domain and transition | Apex on Pages; `www` temporarily serves legacy endpoints and redirects browser content. | DNS/TLS ownership and any clients or integrations using the apex PHP routes. |
| First compatible release | Complete and validate 2.0.0 if still unpublished. | Current release state and whether to offer an NSIS installer immediately or ship the portable package first. |
| Legacy support | Keep a bridge through the announced support window; review after at least 90 days and one quarterly cycle. | Supported old versions, user constraints, and whether eventual zero-server hosting takes priority over old-client online compatibility. |
| Website generation | Small static build, preserved public STIG URLs, validated snapshot inputs. | Existing HTML generator/provenance, content refresh owner, and acceptable site size/traffic budget. |
| Refactor extent | Shared qmake configuration, test extraction, reliable downloads, small worker coordinator, and internal persistence/parser boundaries. | Baseline regressions or measured hotspots that justify additional work. |
| CI and toolchain | Consolidated CI/release workflows, Ubuntu 26.04 Linux runners/images, and static Windows Qt 6.12. | Exact source/patch digests, clean/cache build results, and package compatibility evidence. These upgrade targets are already requested. |

The overhaul is complete when the public site is on Pages with its historical content accessible, current releases are downloadable without relying on CI artifact retention, supported clients retain their promised online/offline workflows, assessment data and markings survive upgrades, the application has fewer duplicated responsibilities, and routine releases/content refreshes have tested recovery procedures. Legacy endpoint retirement is a separate, explicit support milestone.


**Implementation and publication handoff**

| Plan area | Result | Remaining external acceptance |
| --- | --- | --- |
| Stable update check | Desktop checks the live versioned Pages JSON endpoint, validates stable semantics and project release URLs, and never recommends a downgrade. Public stable metadata remains 1.2.7. | Native desktop acceptance before distributing 2.0.0; publish release assets before changing the stable pointer. |
| STIG content continuity | Exact-version catalog, immutable hashes, verified downloads/cache, one temporary quarterly archive reused per checklist import batch, and manual import fallback. | Verify the live endpoint/domain inventory and actual supported legacy clients. |
| Website | Pages preview deployed from its own repository; build, link crawl, five tests, deployment, and live health monitor pass. | DNS cutover, live legacy-client acceptance, production cron and bridge retirement remain separate. |
| Application simplification | Shared qmake configuration; extracted test scenarios, persistence, parsers, serializers, networking, archives and classification; retained UI interfaces/schema/data locations. | Review the diff in these responsibility groups; perform interactive acceptance on supported platforms. |
| Reliability | Worker/SQL cleanup, transactional XCCDF/remapping, atomic project/checklist writes, visible nested-export failures, indexed upgrades, and CKLB status round-trip fix. | Native platform acceptance and the release checklist in `doc/maintenance.md`. |
| Builds and Actions | All four hosted CI jobs pass on Ubuntu 26.04, including the uninterrupted cold Qt 6.12 Windows build, Linux tests/package, CodeQL, and Sonar/Coveralls publishing. Checksummed packages and the Windows cache are uploaded. | Optional branch protection, native Windows execution, actual package installation, and tag-triggered draft-release acceptance. |

See `doc/overhaul-validation.md` for measured results, artifact locations, failures corrected during implementation, and the limits of local evidence. Local validation completed before publication was authorized. The current publication task covers `main`, hosted CI verification, and the Pages preview; the domain cutover and stable desktop release retain their acceptance gates.
