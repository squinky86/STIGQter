# Overhaul validation and publication

This is the review record for the local overhaul, based on application commit `8d575ca`. At the original local handoff, no commits, pushes, remote releases, website deployments, DNS changes, or production-server changes had been made. The maintainer has since authorized publishing `main`, running the hosted checks, and deploying the Pages preview. The measurements below record the local validation; current hosted results are available in GitHub Actions. The plan is in `plan-overhaul.md`; ongoing commands and release gates are in `doc/maintenance.md` and the separate website workspace's `README.md`.

## Implemented scope

- Shared qmake source/resource configuration; production UI scenario code moved to tests; persistence, classification, archive handling, and checklist parsing/writing split behind their existing interfaces.
- Bounded, TLS-verified downloads; static stable-release and exact STIG catalog contracts; verified catalog cache and temporary quarterly-archive reuse within each import batch; explicit failure reporting and manual import fallback.
- Latest-stable checks use `https://squinky86.github.io/stigqter.com/metadata/v1/releases.json`. This Pages endpoint is now live and verified anonymously. Metadata still advertises the actually published stable 1.2.7; source version 2.0.0 remains unreleased. Older published versions never trigger a downgrade prompt.
- Worker/thread/SQL cleanup; XCCDF imports moved off the GUI thread with transactional updates and selection preservation; remapping transactions; atomic project/checklist writes; indexed checklist upgrades.
- Two application workflows (CI and draft release), shared build scripts, explicit Ubuntu 26.04 runners, pinned static Qt 6.12 Windows sources, and separate Pages build/deployment/monitoring in the website workspace.
- Static historical website, immutable metadata/catalog generation, current public DISA content inventory, repaired legacy PHP contracts, rollback snapshots, and operator handoff.

Application name, absence of a Qt organization name, default/portable data locations, schema version 10, UI forms/object names, embedded control catalogs, and version 2.0.0 are unchanged. No maintainer assessment database was used. Source validation used shadow builds, and the root application was also rebuilt for local review. Generated Makefiles/objects/resources/binaries remain ignored and were not manually edited or staged. Review artifacts are ignored under `.build/`.

## Linux and application evidence

Environment: Ubuntu 26.04.1, GCC 15.2, Qt 6.10.2, libzip 1.11.4, libxlsxwriter 1.2.4. The requested Qt 6.12 upgrade applies to the static Windows toolchain; Linux uses Ubuntu's Qt development packages.

The original integration suite passed **19 tests, zero failures** in 162.7 seconds. The expanded suite runs with unique application identity, isolated settings/data/cache and disposable fixture/output directories, using Qt's offscreen platform here. It does not download the live quarterly archive. Text and JUnit results are in `.build/results/tests.txt` and `.build/results/tests.xml`.

The expanded tests exercise the existing assessment/report workflow plus HTTP status/redirect/loop/disconnect/timeout/size failures, untrusted TLS, stable-version validation, exact catalog matching/cache recovery/checksums and repeated member extraction after the original archive becomes unavailable, corrupt ZIPs, worker failure/connection cleanup, XCCDF parsing and rollback, remapping rollback, schema 9→10 project migration, future-schema rejection, failed/active-database snapshot writes, CKL serialization and CKLB round trips, nested export failures, and upgrade field/marking preservation. Bulk-export tests also verify files are created in both formats/modes; normalized forward-slash containment fixes an existing Windows separator mismatch that could silently skip exports. The tests found and fixed CKLB `not_a_finding` being re-imported as Not Reviewed. Upgrade indexing preserves the previous first-match behavior while avoiding repeated nested database queries.

Timing is diagnostic only: the suite has more cases than the baseline and other builds ran concurrently. Do not interpret whole-suite times as a controlled performance benchmark.

Final application/test builds passed. The final expanded run passed **30 tests, zero failures/skips** in **252.059 seconds** while the clean Windows build and package build ran concurrently. The ASD upgrade fixture preserves status, comments, findings, override/justification, and marking; its timing is recorded in the test log.

The Ubuntu `.deb` builds successfully from a clean POSIX staging copy, with tracked Git file modes restored. Local debhelper tools were extracted without privilege and `LOCAL_UNPRIVILEGED_PACKAGE=1` skipped only the installed build-dependency check; CI installs those dependencies normally. `apt-get --simulate install` resolves the package without removals. The extracted binary resolves all shared libraries, starts offscreen for five seconds, and creates a valid SQLite database in an isolated data directory. `PRAGMA quick_check` passes. This smoke run terminates the temporary process after startup; it is not a graceful-shutdown or system-install test.

Review artifacts are under `.build/dist/`: the Ubuntu 26.04 amd64 `.deb`, clean source archive, Windows portable `.exe`/`.zip`, and SHA-256 lists. Package inspection, install simulation, startup evidence, PE checks, and Qt Test logs are under `.build/results/`.

## Windows toolchain validation

The initial source build produced matching host and target **Qt 6.12.0** and a linked Windows application using the manifest-pinned dependencies. PE inspection passes the Windows-system-DLL allowlist and required ASLR, DEP, and high-entropy-VA flags (`0x0160`). Control Flow Guard is not emitted by this MinGW toolchain and is informational in the checker. Static plugin registration includes Windows integration, SQLite, OpenSSL and Schannel.

Two toolchain compatibility corrections are included: a scoped libzip `DWORD_MAX` definition for the selected MinGW headers, and direct host-qmake invocation with `target_qt.conf` because Qt's generated cross wrapper splits quoted compiler assignments. The reviewed system-library allowlist includes Qt 6.12's [Direct3D 12](https://learn.microsoft.com/en-us/windows/win32/api/d3d12/nf-d3d12-d3d12createdevice) and [Windows color management](https://learn.microsoft.com/en-us/windows/win32/api/icm/nf-icm-opencolorprofilew) imports. Non-system runtime DLLs remain forbidden.

Both local attempts to compile the complete toolchain from clean sources reached the target plugins but exceeded this environment's per-user temporary-filesystem quota while writing precompiled headers. The second attempt used the final script's host-build cleanup and still needed the local storage workaround. The target build then completed and installed after relocating only its temporary precompiled headers to disk; source/configuration/compiler flags were unchanged. The application build directory was cleared for a fresh application compilation against that completed toolchain. This local evidence is successful source compilation with a documented resume. The subsequent hosted cold run completed uninterrupted on the normal runner workspace; see the publication evidence below.

The fresh Windows application build and portable EXE/ZIP packaging pass. A repeat run reuses the toolchain in 4.15 seconds. After removing Qt source/build scratch directories and the application build directory, a **fresh application build using only the installed toolchain cache passes in 63.12 seconds**; its EXE SHA-256 matches the previous build. This validates the installed cache rather than depending on leftover Qt build files.

The cache check exposed `strip` rewriting the PE timestamp. Packaging now uses `--preserve-dates`, retaining the linker's zero timestamp; the PE checker enforces that property. The prepared toolchain was reused for this packaging-only correction, which does not change its source/configuration/compiler flags. Repeat packaging and the fresh cache build produce the same executable bytes. ZIP container timestamps are not claimed reproducible.

Temporary Qt precompiled headers and source/build scratch directories were removed after installation. The installed local toolchain and verified source downloads remain under `/tmp/stigqter-overhaul/`; these temporary paths are evidence from this session, not permanent release infrastructure. The uninterrupted hosted cold build has now passed. Native Windows execution remains required before publishing a stable desktop release.

## Website and content evidence

Website changes were prepared in `/mnt/win/projects/websites/stigqter.com`; this directory was not a Git repository at the start. It now publishes to `squinky86/stigqter.com`. Original changed/removed PHP and shell files were backed up under `/tmp/stigqter-overhaul/website-before/`. The built `_site` directory, private `.cache`, backups, and local server configuration are excluded from source commits.

- Five Python/PHP integration tests pass, covering invalid/corrupt/ambiguous/reduced catalogs without manifest replacement, stable-release validation, and real local HTTP legacy contracts including exact nested ZIP retrieval and 404/503 failures.
- PHP syntax checks pass for the three compatibility endpoints and shared metadata helper. Python compilation and shell/workflow syntax checks pass.
- The internal link crawl passes across **20,175 HTML pages**. The static builder preserves those pages, strips historical analytics/advertising scripts from the publication artifact, and excludes PHP, server settings, caches, backups, and assessment data. The built public inputs total **20,194 files / 77,528,628 bytes**, well below the configured 250 MiB budget.
- The October 2026 public quarterly ZIP was downloaded and hashed: **375,827,141 bytes**, SHA-256 `ea581eb2d5c4a210440852b67ea4dd9564fffdf57c8c94aec971047fe0c01d1d`, **399 exact STIG identities**. The preceding verified July manifest/catalog is retained for rollback; immutable catalogs remain published across manifest updates.
- The replacement HTML generator processed all 399 October guides into a separate local preview. The historical published-content snapshot was preserved; it is not represented as an October regeneration.
- The NIST generator's pinned source reproduces the bundled XML byte for byte: 324 controls and 872 enhancements. The embedded file was not changed.

## Hosted publication evidence

Published on 3 November 2026 (America/Chicago), after the maintainer authorized pushing `main` and the Pages preview:

- Application commit [`b6224ac`](https://github.com/squinky86/STIGQter/commit/b6224ac2324e48bc5f3ee49ec8f9877596d58cb7) is on `main`, which is now the default branch. The old `master` branch is retained. A duplicate push-triggered CI run was cancelled before the full manual run to avoid two simultaneous cold toolchain builds.
- [Full hosted CI](https://github.com/squinky86/STIGQter/actions/runs/41772281141) exercises all four jobs on Ubuntu 26.04. Linux build/test/package and CodeQL pass. The ordinary integration run passes all 30 tests in 63.985 seconds; the instrumented run passes all 30 in 69.097 seconds. Downloaded Ubuntu package/source artifacts pass their SHA-256 checks.
- The static Windows Qt 6.12.0 job passes from an empty cache in **46 minutes 1 second**, including dependency/host/target builds, application compilation, portable packaging, and cache upload. The downloaded EXE/ZIP pass their SHA-256 checks; hosted PE validation confirms only Windows system imports, ASLR/DEP/high-entropy VA, and a zero build timestamp. The installed toolchain cache is saved successfully under `main` (61,315,474 compressed bytes). No manual build resume or local storage workaround was needed on the hosted runner.
- Coverage generation and both publishers pass. LCOV contains 66 source files and 5,914 covered lines out of 7,176. [Sonar analysis](https://sonarcloud.io/dashboard?id=squinky86_STIGQter&branch=main) reports execution success, and [Coveralls](https://coveralls.io/jobs/190871505) accepts the report from that same test execution.
- The separate website repository publishes commit `cbd2b90b` to [the Pages preview](https://squinky86.github.io/stigqter.com/). [Build/deployment](https://github.com/squinky86/stigqter.com/actions/runs/41772881122) and [manual build/health checks](https://github.com/squinky86/stigqter.com/actions/runs/41772881033) pass. The manual check uses `deploy=false`; the scheduled monitor can now be exercised manually too.
- Anonymous GETs return HTTP 200 for the homepage, logo, historical rule pages, and both metadata manifests. The immutable catalog's SHA-256 matches its manifest and contains 399 entries. The hosted monitor reports `Healthy: stable 1.2.7, 399 STIGs, metadata age 0 days` and checks release/download targets.

Pages uses its project URL with HTTPS and no custom domain yet. No stable desktop release/tag, DNS cutover, or production legacy-host deployment was performed. The draft-release workflow was syntax-checked but deliberately not dispatched without a release candidate tag. Native platform acceptance remains a release gate.

## Remaining release and domain gates

These are remaining acceptance/publication steps, not claims of completed validation:

1. Review the published Pages preview and the application artifacts before shipping the new desktop client. The new update/content endpoints are live; offline/manual fallbacks remain available.
2. Configure branch protection if desired: `main` currently has no required-check rule. The replacement checks are Linux build/tests/package, static Windows Qt 6.12, and CodeQL; weekly/manual coverage publishes successfully using the existing Sonar credential.
3. Perform native Windows startup, SQLite, TLS, import/export/report, shutdown, and compact/large-window acceptance on advertised Windows versions. Cross-compilation and PE inspection do not prove those behaviors. No Windows runtime or Wine is available here; NSIS installation is not part of the portable release pipeline.
4. Install/uninstall the final `.deb` in a disposable Ubuntu 26.04 environment and perform interactive Linux acceptance. Local package construction, dependency simulation, extracted-binary startup, and offscreen tests are narrower evidence.
5. Inventory and back up the live website configuration/DNS/TLS/cron state, assign primary and backup operators, validate actual supported released clients against the legacy bridge, then have the website publisher carry out the reviewed cutover. Local PHP contract tests do not replace live-client acceptance.
6. Publish reviewed release assets first, then the stable metadata pointer. Retain bridge hosting for the announced support window and one quarterly cycle; retirement is a separate support decision. Keep previous complete metadata/artifacts and configuration backups for rollback.
