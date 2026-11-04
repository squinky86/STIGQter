// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QByteArray>
#include <QString>
#include <QUrl>
#include <QVersionNumber>

namespace ReleaseMetadata {
struct StableRelease {
    QVersionNumber version;
    QUrl page;
};
QUrl siteUrl();
QUrl latestUrl();
bool parse(const QByteArray &json, StableRelease &release, QString &error);
bool isNewer(const StableRelease &release, const QString &currentVersion);
}
