# STIGQter

[STIGQter](https://stigqter.com/) is an open-source reimplementation of DISA's STIG Viewer. It imports and assesses STIGs, saves CKL/CKLB checklists, and produces reports for eMASS and other compliance workflows.

STIG checks are mapped to CCIs and rolled up against the NIST SP 800-53 Revision 5 control catalog (RMF). The bundled control set (`src/800-53-rev5-controls.xml`) is regenerated from NIST's authoritative OSCAL catalog via `scripts/generate_rev5_controls.py`.

## Installation

Download published versions from [GitHub Releases](https://github.com/squinky86/STIGQter/releases/latest). The version in this checkout may still be unreleased. CI artifacts are development builds and expire; they are not the stable download channel.

The release workflow prepares a portable Windows x64 executable/ZIP using static Qt 6.12, an Ubuntu 26.04 amd64 `.deb`, and a source archive. CI runs native Windows integration and portable-startup tests, checks live Pages TLS, and installs/removes the Ubuntu package before preparing a release draft. Other Debian/Ubuntu versions and the existing Gentoo/NSIS packaging need their own validation; the Ubuntu package does not establish compatibility with Kali or older Debian releases.

The source has the following dependencies (with minimum version numbers):

*   [libzip 1.5.1](https://libzip.org/)
*   [libxlsxwriter 0.8](https://libxlsxwriter.github.io/)
*   [Qt 6.9 (with OpenSSL support)](https://www.qt.io/)

Build with `qmake6 STIGQter.pro` and `make`, or use `bash scripts/ci/build-linux.sh` for separate build directories. On Ubuntu 26.04, `bash scripts/ci/setup.sh linux` installs development dependencies. Build the tests through the same script, then run `bash scripts/ci/test.sh`; it provides disposable fixture/output directories and isolated settings. Do not run tests beside a portable `STIGQter.db`.

Update checks read `https://squinky86.github.io/STIGQter/metadata/v1/releases.json`. Only a newer published stable release produces an update prompt. Quarterly downloads and automatic missing-STIG lookup use the versioned catalog at the same Pages site. Failed checks do not prevent offline work; manual ZIP imports and custom quarterly URLs remain supported. Automatic downloads verify the archive size and SHA-256. Update checks can still be disabled in Options. The [Pages site](https://squinky86.github.io/STIGQter/) and metadata are live. The stable pointer is updated only after the release packages are published and their public downloads are verified.

The working database remains in the existing application-data directory, or beside the executable when using a portable database. No data-location or schema-version change is part of this overhaul. Back up `.stigqter` snapshots before upgrading.

See [the overhaul plan](plan-overhaul.md), [validation evidence](doc/overhaul-validation.md), and [the maintenance runbook](doc/maintenance.md) for publication status, release checks, and website publishing.

## Documentation and website

The [documentation site](https://squinky86.github.io/STIGQter/docs/) is built from this repository. Website sources are in `site/`; the Pages workflow generates documentation from the Markdown files and publishes the site, historical STIG library, and update metadata together. See the [user guide](doc/user-guide.md) and [website maintenance instructions](site/README.md).

## Authors

*   Jon Hood (squinky86)

## License

[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)
