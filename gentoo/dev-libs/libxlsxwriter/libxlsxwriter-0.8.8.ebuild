# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake-utils l10n

DESCRIPTION="Libxlsxwriter is a C library for creating Excel XLSX files."
HOMEPAGE="http://libxlsxwriter.github.io/"
SRC_URI="https://github.com/jmcnamara/libxlsxwriter/archive/RELEASE_${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="minizip static-libs"
S="${WORKDIR}/${PN}-RELEASE_${PV}"

DEPEND="sys-libs/zlib
	minizip? ( sys-libs/zlib[minizip] )"
RDEPEND="${DEPEND}"

src_prepare() {
	for x in $(l10n_get_locales); do
		if ! [[ "${x}" =~ ^en* ]]; then
			#non-english locale detected; apply l10n patch
			epatch "${FILESDIR}/libxlsxwriter-0.8.7-double-function.patch"
		fi
	done
}

src_configure() {
	local mycmakeargs=(
		-DCMAKE_BUILD_TYPE=Release
		-DUSE_SYSTEM_MINIZIP="$(usex minizip)"
		-DBUILD_SHARED_LIBS="$(usex static-libs OFF ON)"
		-DUSE_DOUBLE_FUNCTION=ON
	)
	cmake-utils_src_configure
}

src_install() {
	cmake-utils_src_install
	dodoc CONTRIBUTING.md License.txt Readme.md Changes.txt
	dodoc -r docs examples
}
