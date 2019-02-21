# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

# This ebuild was created by Jon Hood <jwh0011@auburn.edu>, a former Gentoo
# developer (squinky86) under the Gentoo Foundation. Copyright for this ebuild
# is hereby assigned to the Gentoo Foundation.

EAPI=7

inherit qmake-utils

DESCRIPTION="STIGQter is an open-source reimplementation of DISA's STIG Viewer."
HOMEPAGE="https://github.com/squinky86/STIGQter"
SRC_URI="https://github.com/squinky86/STIGQter/archive/${PV}-beta.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

MY_PN="STIGQter"
S="${WORKDIR}/${MY_PN}-${PV}-beta"

DEPEND="
	>=app-text/tidy-html5-5.6
	>=dev-libs/libxlsxwriter-0.8
	>=dev-libs/libzip-1.3
	>=dev-qt/qtgui-5
	sys-libs/zlib"
RDEPEND="
	>=app-text/tidy-html5-5.6
	>=dev-libs/libxlsxwriter-0.8
	>=dev-libs/libzip-1.3
	>=dev-libs/openssl-1
	>=dev-qt/qtgui-5"
BDEPEND=""

src_configure() {
	eqmake5 ${MY_PN}.pro
}

src_install() {
	emake INSTALL_ROOT="${D}" install
}
