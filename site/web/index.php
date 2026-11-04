<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>STIGQter: STIG Fun with Qt</title>
	<link rel="icon" type="image/svg+xml" href="STIGQter.svg" />
	<meta name="description" content="Open Source Reimplementation of STIG Viewer" />
	<script async src="https://www.googletagmanager.com/gtag/js?id=UA-31381839-2"></script>
	<script src="include.js"></script>
	<script data-ad-client="ca-pub-4110907817782130" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>
	<style>
		:root {
			--primary-color: #2c3e50;
			--link-color: #3498db;
			--link-hover: #2980b9;
			--bg-color: #f4f7f6;
			--container-bg: #ffffff;
			--text-color: #333333;
			--border-color: #e1e8ed;
		}
		body {
			font-family: 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
			line-height: 1.6;
			color: var(--text-color);
			background-color: var(--bg-color);
			margin: 0;
			padding: 2rem 1rem;
		}
		.container {
			max-width: 800px;
			margin: 0 auto;
			background: var(--container-bg);
			padding: 2.5rem 3rem;
			border-radius: 8px;
			box-shadow: 0 4px 12px rgba(0,0,0,0.05);
		}
		h1 {
			color: var(--primary-color);
			display: flex;
			align-items: center;
			gap: 15px;
			margin-top: 0;
			font-size: 2.2rem;
			border-bottom: 2px solid var(--border-color);
			padding-bottom: 1rem;
		}
		h2 {
			color: var(--primary-color);
			border-bottom: 1px solid var(--border-color);
			padding-bottom: 0.5rem;
			margin-top: 2rem;
		}
		a {
			color: var(--link-color);
			text-decoration: none;
			transition: color 0.2s ease;
		}
		a:hover {
			color: var(--link-hover);
			text-decoration: underline;
		}
		p {
			margin-bottom: 1rem;
		}
		.badges {
			display: flex;
			flex-wrap: wrap;
			gap: 10px;
			list-style: none;
			padding: 0;
		}
		.badges li {
			margin: 0;
		}
		ul:not(.badges) {
			padding-left: 1.5rem;
		}
		li {
			margin-bottom: 0.5rem;
		}
		.version-info {
			background: #e8f4f8;
			border-left: 4px solid var(--link-color);
			padding: 1rem;
			border-radius: 4px;
		}
		.version-info p {
			margin: 0;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1><img src="STIGQter.svg" alt="STIGQter" style="height:1.2em;" /> STIGQter</h1>
		<p>STIGQter provides a reimplementation of <a href="https://public.cyber.mil/stigs/srg-stig-tools/">DISA's STIG Viewer</a>. STIGQter is developed using the Qt framework, and its goal is to more accurately mirror the asset management layout of eMASS. This project is not associated with DISA.</p>
		
		<h2>Latest Version</h2>
		<div class="version-info">
			<p><strong>Current Version:</strong> <a href="https://github.com/squinky86/STIGQter/releases/tag/1.2.7">1.2.7</a></p>
		</div>
		<p>Experimental 64-bit Windows builds are available via the <a href="https://github.com/squinky86/STIGQter/actions/workflows/windows.yml">GitHub Actions build artifacts</a>.</p>
		<p>Experimental 64-bit Debian packages are available via the <a href="https://github.com/squinky86/STIGQter/actions/workflows/debian.yml">Debian CI GitHub Action artifacts</a>.</p>
		
		<h2>Bugs and Support</h2>
		<p>For bug reports, support, and any general questions, please <a href="https://github.com/squinky86/STIGQter/issues">file an issue on github</a>.</p>
		
		<h2>STIG Content</h2>
		<p>The NON-FOUO STIGs are publicly released by DISA at <a href="https://public.cyber.mil/">public.cyber.mil</a>. HTML-formatted versions of these STIGs with printable, manual checklists are available <a href="stigs/main.html">here</a>.</p>
		
		<h2>Source</h2>
		<p>The source code for STIGQter is available on <a href="https://github.com/squinky86/STIGQter">github</a>.</p>
		<p>Build status, code quality, and code coverage results:</p>
		<ul class="badges">
			<li><a href="https://github.com/squinky86/STIGQter/actions/workflows/windows.yml"><img src="https://github.com/squinky86/STIGQter/actions/workflows/windows.yml/badge.svg" alt="GitHub Actions Windows Build" /></a></li>
			<li><a href="https://bestpractices.coreinfrastructure.org/projects/3717"><img src="https://bestpractices.coreinfrastructure.org/projects/3717/badge" alt="CCI Best Practices" /></a></li>
			<li><a href="https://www.codacy.com/gh/squinky86/STIGQter/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=squinky86/STIGQter&amp;utm_campaign=Badge_Grade"><img src="https://app.codacy.com/project/badge/Grade/fe95236f03ac47cd83edf4521138317e" alt="Codacy" /></a></li>
			<li><a href="https://codecov.io/gh/squinky86/STIGQter"><img alt="Codecov Code Coverage Statistics" src="https://codecov.io/gh/squinky86/STIGQter/branch/master/graph/badge.svg" /></a></li>
			<li><a href="https://www.codefactor.io/repository/github/squinky86/stigqter"><img src="https://www.codefactor.io/repository/github/squinky86/stigqter/badge" alt="CodeFactor" /></a></li>
			<li><a href="https://github.com/squinky86/STIGQter/actions/workflows/codeql-analysis.yml"><img alt="CodeQL Scan Status" src="https://github.com/squinky86/STIGQter/actions/workflows/codeql-analysis.yml/badge.svg" /></a></li>
			<li><a href="https://coveralls.io/github/squinky86/STIGQter"><img alt="Coveralls Code Coverage Results" src="https://coveralls.io/repos/github/squinky86/STIGQter/badge.svg?branch=master" /></a></li>
			<li><a href="https://scan.coverity.com/projects/squinky86-stigqter"><img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/17663/badge.svg"/></a></li>
			<li><a href="https://github.com/squinky86/STIGQter/actions/workflows/debian.yml"><img alt="Debian Package Build Status" src="https://github.com/squinky86/STIGQter/actions/workflows/debian.yml/badge.svg" /></a></li>
		</ul>
		
		<h2>License</h2>
		<p>STIGQter is under the <a href="https://www.gnu.org/licenses/gpl-3.0.en.html">GPL version 3</a>.</p>
		
		<h2>Contributions</h2>
		<p>Contributions in the form of source code, documentation, bug reports, and any form of encouragement are greatly appreciated and managed on the <a href="https://github.com/squinky86/STIGQter/">GitHub portal</a>.</p>
		<p>Monetary donations are appreciated:</p>
		<ul>
			<li>If you are a government organization or your project benefited from the use of this tool, please consider reaching out to the developers for MIPR information regarding support for your contract.</li>
			<li>If you personally benefited from the use of this tool, please consider donating to <a href="https://www.fisherhouse.org/">Fisher House</a> on behalf of the STIGQter organization or giving to Jon Hood <a href="https://paypal.me/squinky86">directly via PayPal</a> for the support of STIGQter infrastructure and development.</li>
		</ul>
	</div>
</body>
</html>