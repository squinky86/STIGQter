# Using STIGQter

STIGQter organizes an assessment around assets, their STIGs, and the results of individual checks. Keep your working assessment in STIGQter and export the checklist or report format required by your receiving system.

## Install and start

Get published versions from [GitHub Releases](https://github.com/squinky86/STIGQter/releases/latest). See [installation and build instructions](../README.md) for supported packages and source builds. GitHub Actions artifacts are development builds; they are not the stable release channel.

The application keeps its working database in its existing application-data directory. A portable database beside the executable takes precedence. Save `.stigqter` project snapshots for backup and transfer; a CKL or CKLB export serves a different purpose from a complete project snapshot.

## 1. Prepare the RMF controls

The first section of the main window contains NIST controls and DISA CCIs. STIGQter indexes the bundled catalogs on first launch. These records provide the mappings from individual STIG checks to controls. The same section provides eMASS spreadsheet imports when your workflow requires them.

Wait for indexing or imports to finish before starting the next operation. Review any reported errors before relying on imported mappings.

## 2. Load the STIG library

Use **Import STIG(s)** to load a public STIG ZIP, or download the quarterly library through the application. Filter the STIG list by title to find the guides you need. Importing STIG content adds the requirements to your library; assessment results belong to an asset's checklist.

The download catalog identifies exact STIG versions and releases and verifies archive checksums. If the network or a historical download is unavailable, obtain the appropriate ZIP and import it manually. Do not substitute a different release without reviewing the checklist upgrade.

## 3. Create or import an asset

Select the required STIGs and use **Create Asset** to create an assessment with those guides attached. Alternatively, import existing CKL or CKLB checklists from the assets/checklists section.

Open the asset to review its details and attached STIGs. Confirm that the asset identity, STIG versions, and markings are correct before editing results. An import that needs missing STIG content can use the exact-version catalog; if that lookup fails, import the matching STIG ZIP and retry.

## Assess the checks

In the asset tab, filter and select checks, then record the applicable status, finding details, and comments. Review severity overrides and their justification when using them. Use the filters to work through remaining checks and inspect completed results.

Keep the classification banners in view. STIGQter escalates the system marking to the highest asset marking; generated reports also carry markings. Verify the markings and intended destination before sharing an export.

## Save, reopen, and export

Save a project snapshot before significant imports or upgrades and keep a backup outside the working database. Reopen a saved project when moving an assessment between installations or recovering a saved state.

Export CKL or CKLB for checklist exchange. STIGQter also produces eMASS, CMRS, POA&M, findings, and HTML reports. Select the assets and report format that match your recipient's requirements, and inspect the resulting file before submitting it. Retain the project snapshot alongside the exported deliverables.

When upgrading an asset to a newer STIG, review transferred results against the changed requirements. Matching identifiers help preserve assessment work, but they do not establish that a changed check has been reassessed.

## Updates and offline use

The optional update check reads the [stable release manifest](https://squinky86.github.io/STIGQter/metadata/v1/releases.json). It prompts only for a newer published stable release. You can disable update checks in Options. A failed update check does not prevent offline assessment work.

If a download fails, keep your current project, review the error, and use manual import when suitable. For an application problem, report the steps and version through [GitHub Issues](https://github.com/squinky86/STIGQter/issues). Follow the [security policy](../SECURITY.md) for vulnerabilities. Avoid posting assessment databases or sensitive findings in public issues.
