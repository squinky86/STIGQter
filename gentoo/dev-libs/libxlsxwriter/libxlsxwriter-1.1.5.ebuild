# Copyright 1999-2023 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake plocale

DESCRIPTION="Libxlsxwriter is a C library for creating Excel XLSX files."
HOMEPAGE="http://libxlsxwriter.github.io/"
SRC_URI="https://github.com/jmcnamara/libxlsxwriter/archive/RELEASE_${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="minizip mmap openssl static-libs"
S="${WORKDIR}/${PN}-RELEASE_${PV}"

DEPEND="sys-libs/zlib
	minizip? ( sys-libs/zlib[minizip] )"
RDEPEND="${DEPEND}"

src_prepare() {
	cmake_src_prepare
}

src_configure() {
	DOUBLEFUNCTION=OFF
	for x in $(plocale_get_locales); do
		if ! [[ "${x}" =~ ^en* ]]; then
			#non-english locale detected; apply double function fix
			DOUBLEFUNCTION=ON
			break
		fi
	done
	local mycmakeargs=(
		-DCMAKE_BUILD_TYPE=Release
		-DUSE_SYSTEM_MINIZIP="$(usex minizip)"
		-DUSE_MEM_FILE="$(usex mmap OFF ON)"
		-DUSE_OPENSSL_MD5="$(usex openssl OFF ON)"
		-DBUILD_SHARED_LIBS="$(usex static-libs OFF ON)"
		-DUSE_DTOA_LIBRARY=${DOUBLEFUNCTION}
	)
	cmake_src_configure
}

src_install() {
	cmake_src_install
	dodoc CONTRIBUTING.md License.txt Readme.md Changes.txt
	dodoc -r docs examples
}
