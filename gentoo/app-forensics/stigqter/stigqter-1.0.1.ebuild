# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit qmake-utils desktop

DESCRIPTION="STIGQter is an open-source reimplementation of DISA's STIG Viewer."
HOMEPAGE="https://www.stigqter.com/"
SRC_URI="https://github.com/squinky86/STIGQter/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="doc"

MY_PN="STIGQter"
S="${WORKDIR}/${MY_PN}-${PV}"

CDEPEND="
	>=app-text/tidy-html5-5.6
	>=dev-libs/libxlsxwriter-0.8
	>=dev-libs/libzip-1.3
	>=dev-qt/qtgui-5"
DEPEND="${CDEPEND}
	sys-libs/zlib
	doc? (
		dev-texlive/texlive-luatex
		dev-texlive/texlive-fontsextra
		dev-tex/biber
	)"
RDEPEND="${CDEPEND}
	>=dev-libs/openssl-1"

src_configure() {
	eqmake5 ${MY_PN}.pro -r PREFIX="/usr"
}

src_compile() {
	default
	use doc && pushd doc && ./build.sh && popd
}

src_install() {
	emake INSTALL_ROOT="${D}" install
	doicon src/STIGQter.svg
	domenu STIGQter.desktop
	use doc && dodoc doc/UsersGuide.pdf
}
