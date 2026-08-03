# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

# Prebuilt binary ebuild for config-sync.
# Place in an overlay: app-misc/config-sync-bin/config-sync-bin-0.1.0.ebuild
# Install: emerge -a config-sync-bin

EAPI=8

DESCRIPTION="Sync config files across machines with post-quantum E2E encryption"
HOMEPAGE="https://github.com/gregnazario/config-sync"
SRC_URI="https://github.com/gregnazario/config-sync/releases/download/v${PV}/config-sync-x86_64-unknown-linux-gnu-v${PV}.tar.gz"

LICENSE="MIT Apache-2.0"
SLOT="0"
KEYWORDS="~amd64"
IUSE=""

# Prebuilt binary — already stripped, skip QA checks.
RESTRICT="strip"

DEPEND=""
RDEPEND="sys-apps/dbus"
BDEPEND=""

src_install() {
    dobin "${WORKDIR}/config-sync"
    einstalldocs
}
