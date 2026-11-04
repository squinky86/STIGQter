// SPDX-License-Identifier: GPL-3.0-or-later
#include "releasemetadata.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

QUrl ReleaseMetadata::siteUrl()
{
    return QUrl(QStringLiteral("https://squinky86.github.io/stigqter.com/"));
}

QUrl ReleaseMetadata::latestUrl()
{
    return siteUrl().resolved(QUrl(QStringLiteral("metadata/v1/releases.json")));
}

bool ReleaseMetadata::parse(const QByteArray &json, StableRelease &release, QString &error)
{
    release = {};
    error.clear();
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(json, &parseError);
    const QJsonObject root = document.object();
    const QJsonObject stable = root.value(QStringLiteral("stable")).toObject();
    const QString version = stable.value(QStringLiteral("version")).toString();
    const QUrl page(stable.value(QStringLiteral("url")).toString());
    static const QRegularExpression versionPattern(QStringLiteral("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"));
    const QVersionNumber number = QVersionNumber::fromString(version);
    const QUrl expectedPage(QStringLiteral("https://github.com/squinky86/STIGQter/releases/tag/") + version);
    if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
        root.value(QStringLiteral("schema_version")).toDouble() != 1 ||
        !versionPattern.match(version).hasMatch() || number.segmentCount() != 3 ||
        !stable.value(QStringLiteral("prerelease")).isBool() ||
        stable.value(QStringLiteral("prerelease")).toBool() || page != expectedPage) {
        error = QStringLiteral("The stable-release metadata is invalid or unsupported.");
        return false;
    }
    release.version = number;
    release.page = page;
    return true;
}

bool ReleaseMetadata::isNewer(const StableRelease &release, const QString &currentVersion)
{
    const QVersionNumber current = QVersionNumber::fromString(currentVersion);
    return !current.isNull() && QVersionNumber::compare(release.version, current) > 0;
}
