# STIGQter

[STIGQter](https://www.stigqter.com/) is an open-source reimplementation of DISA's STIG Viewer. It is used to generate STIG Checklist files (CKLs) and build finding reports. These reports can then be used to determine compliance in eMASS.

## Installation

Only the source package is supported. To help with implementations, different installation options are provided:
*   64-bit Windows standalone binary and installer (tested on Windows 10)
*   ebuilds for Gentoo Linux (tested on unstable ~amd64)
*   64-bit Debian packages (tested on Ubuntu and Kali)

The source has the following dependencies (with minimum version numbers):
*   [HTML Tidy 5.6](http://www.html-tidy.org/)
*   [libzip 1.5.1](https://libzip.org/)
*   [libxlsxwriter 0.8](https://libxlsxwriter.github.io/)
*   [Qt 5](https://www.qt.io/)
*   [OpenSSL 1](https://www.openssl.org/)

## Authors

*   Jon Hood (squinky86)

## License

[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)
