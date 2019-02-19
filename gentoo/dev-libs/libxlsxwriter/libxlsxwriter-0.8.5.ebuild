# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

# This ebuild was created by Jon Hood <jwh0011@auburn.edu>, a former Gentoo
# developer (squinky86) under the Gentoo Foundation. Copyright for this ebuild
# is hereby assigned to the Gentoo Foundation.

EAPI=7

inherit cmake-utils

DESCRIPTION="Libxlsxwriter is a C library for creating Excel XLSX files."
HOMEPAGE="http://libxlsxwriter.github.io/"
SRC_URI="https://github.com/jmcnamara/libxlsxwriter/archive/RELEASE_${PV}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""
S="${WORKDIR}/${PN}-RELEASE_${PV}"

CDEPEND="sys-libs/zlib"
DEPEND="${CDEPEND}"
RDEPEND=""

src_configure() {
	cmake-utils_src_configure
}

src_install() {
	cmake-utils_src_install
}
