# STIGQter website and documentation

The website lives in `site/` in the **squinky86/STIGQter** repository. The root `.github/workflows/pages.yml` builds and deploys it to [STIGQter Pages](https://squinky86.github.io/STIGQter/). No second repository, submodule, Jekyll service, or external source checkout is required.

The public artifact combines the historical STIG library, versioned desktop metadata, and HTML documentation generated from the repository's Markdown files. Edit the Markdown sources, not generated HTML. The documentation includes the [user guide](../doc/user-guide.md), [installation instructions](../README.md), release notes, security policy, and maintenance guides. The LaTeX design/security sources remain in `doc/` and are linked from the documentation index.

## Build and preview

Run these commands from the STIGQter repository root. The builder needs Python 3 and Python-Markdown; compatibility tests also need PHP with ZIP support. On Ubuntu 26.04, install `python3-markdown php-cli php-zip`.

```bash
python3 site/scripts/build_site.py
python3 site/scripts/check_site.py site/_site --base-url https://squinky86.github.io/STIGQter/
python3 -m unittest discover -s site/scripts -p 'test_*.py'
```

The output is `site/_site/` and is ignored by Git. Preview it locally with:

```bash
python3 -m http.server --bind 127.0.0.1 --directory site/_site 8080
```

Open `http://127.0.0.1:8080/`. Navigation and stylesheet links work relative to the preview; canonical URLs and absolute historical links identify the deployed site. The link checker also validates absolute links within the configured Pages base URL against the local artifact.

The builder copies an explicit public-file allowlist, strips obsolete analytics/advertising scripts from the historical HTML, generates documentation and a sitemap, and enforces a 250 MiB artifact budget. PHP, caches, server configuration, backups, and assessment data are excluded. It preserves the 20,175 historical HTML pages and adds the generated documentation. The source snapshot is about 75 MiB.

## Pages workflow

Pages must use **GitHub Actions** as its publishing source in this existing repository, and the `github-pages` environment must permit deployments from `main`. The `Pages` workflow builds and validates relevant pull requests, deploys relevant pushes to `main`, and runs health checks after deployment. A manual run defaults to `deploy=false`, which checks the build and current live site; set `deploy=true` to publish. Weekly health checks run without rebuilding the site.

The default URL is `https://squinky86.github.io/STIGQter/`. The desktop's `ReleaseMetadata::siteUrl()` uses that exact address for release and content metadata. The link crawl checks project-prefix URLs as well as relative links, including the documentation, styles, logo, and custom 404 page. Workflow failures must be reviewed by the primary or backup maintainer; check the most recent scheduled run and metadata age during routine maintenance.

## Content refresh

Stable metadata describes the latest verified, published GitHub release; it is never inferred from the development `VERSION` file. The reviewed October 2026 public DISA bundle contains 399 exact STIG identities and 375,827,141 bytes, SHA-256 `ea581eb2d5c4a210440852b67ea4dd9564fffdf57c8c94aec971047fe0c01d1d`. The preceding July manifest is retained in `site/metadata-history/2026-07-content.json`; older immutable catalogs remain available for cached clients and rollback.

Download only the public quarterly archive using normal TLS verification. Do not use user databases, restricted content, assessment exports, or server backups as publication inputs.

```bash
python3 site/scripts/content_metadata.py /path/to/public-quarterly.zip \
  --url https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_October_2026.zip \
  --release 'October 2026' --stage-legacy
python3 site/scripts/render_library.py /path/to/public-quarterly.zip --output /path/to/new-library-preview
python3 -m unittest discover -s site/scripts -p 'test_*.py'
python3 site/scripts/build_site.py
python3 site/scripts/check_site.py site/_site --base-url https://squinky86.github.io/STIGQter/
```

Review identities, counts, source URL/hash, generated pages, and links before committing. Empty, corrupt, ambiguous, or more-than-10%-reduced catalogs fail without replacing the manifest. `--allow-reduction` requires an intentional review. Preserve complete previous metadata and archives for rollback. The private `site/.cache/archives/` staging area is ignored and never published.

The historical HTML has separate provenance from the current downloadable catalog. Do not describe those pages as an October regeneration. Render into a new staging directory, review it, then merge approved pages into `site/web/stigs/` without deleting historical URLs. `site/scripts/updateHrefs.sh` requires an explicit archive, URL, and release label; the former insecure unattended scraper is retired.

## Stable release metadata

After reviewed desktop packages are public, run `python3 site/scripts/release_metadata.py`. It reads GitHub's latest published release, rejects drafts/prereleases or missing packages/digests, and does not copy the development `VERSION` into stable metadata. Use `--input` with a saved API response for offline reproduction. Verify anonymous downloads, review the diff in `site/web/metadata/v1/releases.json`, then publish through the normal main-branch workflow.

## Custom domain and legacy compatibility

The Pages preview can be tested before changing DNS. The existing production host and its PHP routes remain separate from static Pages hosting. The supplied `site/legacy/` files and PHP endpoints are compatibility deployment inputs, not Pages content.

Before a domain cutover, inventory and back up the live routes, document root, TLS renewal, DNS, cron jobs, and endpoint usage. The original local files differed from the live update endpoint. Keep private backups outside this repository and assign primary and backup operators.

Deploy and test the compatibility bridge on **www.stigqter.com** before moving the apex domain. Adapt `site/legacy/nginx.locations.conf` to the existing server; do not replace shared server configuration. Stage the verified archive and hash sidecar outside the document root, then the catalog and endpoints, replacing `content.json` last. Preserve the existing `web/`, `legacy/`, and `.cache/` relationships on that host. Validate actual supported desktop clients as well as the local synthetic PHP tests.

The old contracts remain: `update.php` returns plain `OK` or a stable version; `stig.php` redirects to the verified quarterly ZIP; `autostig.php?stig=...` returns an exact STIG download URL, and `fn` redirects. Unknown identities return 404; inconsistent or unavailable archives return 503. Pages cannot execute these PHP contracts.

Configure **stigqter.com** in this repository's Pages settings and use [GitHub's custom-domain instructions](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site) for DNS and HTTPS. Leave **www** on the compatibility host. Set the repository variable `SITE_BASE_URL=https://stigqter.com/` and redeploy when the domain is ready. Set `CHECK_LEGACY=true` only after the bridge is deployed and tested. Keep the project Pages URL usable for desktop clients through GitHub's custom-domain routing.

Retain bridge hosting for the announced support window and at least one quarterly cycle after the compatible release. Review the proposed 90-day minimum against supported deployments. Retirement is a separate support decision; traffic alone cannot establish that infrequent/offline clients have upgraded.

For rollback, restore the previous complete artifact/metadata and matching bridge archive, or restore the old apex DNS while keeping `www` and TLS renewal working. Do not retire shared hosting services used by other websites. Domain cutover, a stable desktop release, and legacy retirement remain separate acceptance steps.
