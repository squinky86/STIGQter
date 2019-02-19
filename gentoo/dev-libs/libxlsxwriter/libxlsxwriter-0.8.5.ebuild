# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake-utils

DESCRIPTION="Libxlsxwriter is a C library for creating Excel XLSX files."
HOMEPAGE="http://libxlsxwriter.github.io/"
SRC_URI="https://github.com/jmcnamara/libxlsxwriter/archive/RELEASE_${PV}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="minizip static-libs"
S="${WORKDIR}/${PN}-RELEASE_${PV}"

CDEPEND="sys-libs/zlib"
DEPEND="${CDEPEND}"
RDEPEND="minizip? ( sys-libs/zlib[minizip] )"

src_configure() {
	local mycmakeargs=(
		-DCMAKE_BUILD_TYPE=Release
		-DUSE_SYSTEM_MINIZIP="$(usex minizip)"
		-DBUILD_SHARED_LIBS="$(usex static-libs OFF ON)"
	)
	cmake-utils_src_configure
}
