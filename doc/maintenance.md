# Maintenance and release handoff

The maintainer authorized publishing the overhaul to `main` and deploying the GitHub Pages preview. Keep `VERSION` at 2.0.0 until the desktop release decision; published stable metadata remains 1.2.7. Domain cutover, legacy-host changes, and a stable desktop release remain separate acceptance steps.

## Build and verify

```bash
bash scripts/ci/setup.sh linux
bash scripts/ci/build-linux.sh
bash scripts/ci/test.sh
bash scripts/ci/package-linux.sh

bash scripts/ci/setup.sh windows
bash scripts/ci/build-windows.sh
```

Builds and results go under `.build/`; generated files at the repository root are not modified. `BUILD_DIRECTORY`, `PACKAGE_BUILD_DIRECTORY`, `WINDOWS_BUILD_DIRECTORY`, `WINDOWS_TOOLCHAIN_DIRECTORY`, and `BUILD_JOBS` support local shadow builds; use absolute paths for directory overrides. Packaging on an NTFS mount needs a POSIX staging directory, for example `PACKAGE_BUILD_DIRECTORY=$(mktemp -d)`. Source archives are captured before compilation, and staged file modes come from Git. An unprivileged local package check may supply debhelper through `PATH`/`PERL5LIB` and set `LOCAL_UNPRIVILEGED_PACKAGE=1`; CI installs and checks dependencies normally.

Tests use a unique application name and refuse a portable database beside the test binary. The runner copies fixtures into a temporary working directory and writes text/JUnit results to `.build/results/`. It uses Xvfb when available, otherwise Qt's offscreen platform. The suite checks real UI workflows, parsers, reports, mappings, classification, project recovery, local HTTP failures, and transaction rollback. The default regression suite does not require live DISA downloads.

The Windows source manifest is `scripts/ci/sources.json`: Qt 6.12.0 plus its reviewed QtBase fix, OpenSSL, libzip, libxlsxwriter, and zlib-ng. Every source/patch download is checksum-verified. Host and target qmake versions must agree. The script calls the host qmake with the target configuration to preserve quoted compiler assignments, and removes the completed host build before starting the target to limit peak disk use. libzip 1.12.1 needs a scoped `DWORD_MAX=0xffffffffUL` definition with the Ubuntu MinGW headers; it represents the existing 32-bit Windows write limit. The build preserves the zero PE timestamp while stripping symbols and verifies PE imports and ASLR/DEP/high-entropy flags and includes source URLs/digests in the ZIP. Review licenses and supply corresponding source when distributing GPL binaries.

After a source/version/configuration change, check a cold toolchain build and a second cache-reuse build. Use a disk-backed working directory with room for Qt precompiled headers; a quota-limited RAM-backed `/tmp` can fail even when `df` reports space available. Hosted CI uses the runner workspace. For cache acceptance, also rebuild the application from an empty application build directory with only the installed toolchain retained; stale build files must not be needed. Before publication, test the executable on supported Windows systems: portable SQLite database, normal data directory, TLS download, CKL/CKLB import/export, report output, and shutdown during a download. Do not infer native Windows success from cross-compilation. The automated Windows package is portable; NSIS installation is not advertised by this pipeline.

## Release sequence after review

1. Confirm the website repository name and publish its metadata preview. Verify the application URL `https://squinky86.github.io/stigqter.com/metadata/v1/releases.json` anonymously. The website has its own repository and publisher; do not deploy it from this project.
2. Review this checkout, run CI, and update branch protection to the `CI` Linux, Windows, and CodeQL checks after they have run successfully. Old workflow names are removed. Weekly/manual coverage uses one instrumented test run for Sonar and Coveralls; configure `SONAR_TOKEN` for Sonar publishing.
3. Update `VERSION`, changelog, release notes, and packaging only for the approved release. Push an exact numeric tag or run `Release candidate` for an existing tag. It verifies tag/VERSION agreement, calls the same CI build scripts, checks hashes, and creates a **draft** GitHub release.
4. Install the `.deb` on Ubuntu 26.04 and run the native Windows checks above. Check compact and large windows, keyboard navigation, both marking banners, warning/busy states, and exports. Record results against the exact tag/artifact hashes.
5. Publish the reviewed release assets. Then run the website's `release_metadata.py`, review its diff, and publish the stable pointer. Do not copy the source `VERSION` directly into public stable metadata. Drafts/prereleases are rejected; each binary asset must have a SHA-256 digest.
6. The website maintainer handles apex DNS/HTTPS cutover and retains the `www` PHP bridge for supported old clients. Keep rollback DNS, web content, metadata, and binary artifacts available. Do not retire shared hosting services used by other sites.

## Data and architecture

`stigqter-common.pri` owns shared source/forms/resources. Production UI classes retain their object names and signal interfaces; scenario code is in `tests/uiscenarios.cpp`. `download`, `releasemetadata`, and `contentcatalog` own network/metadata contracts. `archive.cpp` bounds extraction and rejects incomplete reads; `classification.cpp` contains the unchanged marking conversions.

`DbManager` remains the persistence facade. Its implementation is split into lifecycle/logging, schema, project validation/save/load, queries, mutations, and assessment transactions. The schema remains 10. The legacy `DelayCommit` method toggles SQLite performance pragmas and is **not** a transaction; do not nest new transactions around legacy mutators that call `commit()`. The new XCCDF and bulk-remapping paths use explicit transactions and rollback tests. Broader transaction conversion requires characterization of the affected mutators first.

CKL/CKLB serializers are separate from worker orchestration, and workers own atomic output files. Format names, markings, and fields are preserved. Checklist upgrades index old assessment results by vulnerability ID instead of repeatedly querying SQLite in a nested loop; duplicate IDs retain the former first-match behavior.

Workers are deleted on thread completion; SQL connections close in their owning thread. `ConnectThreads` still owns busy-state coordination. Shutdown requests interruption and waits for running work; downloads have deadlines. Long workers that cannot interrupt immediately finish before their threads are destroyed.

## Content and recovery

The NIST generator defaults to commit `78650f02ad9321bb7b817846f8fbd4f2bcd620de`, SHA-256 `01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062`. It reproduces the bundled 324 controls and 872 enhancements byte for byte. A different remote source requires `--sha256`; local JSON inputs remain supported. Generate to a temporary file and review mapping differences before replacing the bundled XML. CCI updates continue through the existing embedded catalog/import workflow.

Back up user projects before releasing. Load validation/migration runs against a temporary database; invalid or incompatible snapshots leave the active database intact. Snapshot writes use atomic replacement. If a future schema migration is added, test fresh and prior schemas and retain a pre-migration backup; binary rollback alone is insufficient when an older binary cannot read a newer schema.

For metadata rollback, republish the previous complete manifest/catalog pair and stable pointer. Clients validate immutable catalog hashes and retain the last usable pair; custom URLs and manual imports remain available. A checklist import batch reuses one verified quarterly archive in a temporary file, removed when the operation ends; it does not download the same bundle for each missing STIG. A missing exact STIG identity must be supplied manually rather than substituted with a newer release.
