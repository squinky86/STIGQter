// SPDX-License-Identifier: GPL-3.0-or-later
#include "contentcatalog.h"
#include "common.h"
#include "download.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>
#include <QTemporaryFile>

namespace {
bool digestValid(const QString &digest)
{
    static const QRegularExpression pattern(QStringLiteral("^[0-9a-f]{64}$"));
    return pattern.match(digest).hasMatch();
}
QString catalogName(const QJsonObject &manifest)
{
    const auto catalog = manifest.value(QStringLiteral("catalog")).toObject();
    const QString digest = catalog.value(QStringLiteral("sha256")).toString();
    const QString path = catalog.value(QStringLiteral("path")).toString();
    return digestValid(digest) && path == QStringLiteral("catalog-%1.json").arg(digest) ? path : QString();
}
QByteArray read(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 32 * 1024 * 1024) return {};
    return file.readAll();
}
bool save(const QString &path, const QByteArray &bytes)
{
    QSaveFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size() && file.commit();
}
}

ContentCatalog::ContentCatalog(const QUrl &site, const QString &cache) : _site(site)
{
    const QString root = cache.isEmpty() ? QStandardPaths::writableLocation(QStandardPaths::CacheLocation) : cache;
    _cache = root + QStringLiteral("/content-") + QString::fromLatin1(QCryptographicHash::hash(site.toEncoded(), QCryptographicHash::Sha256).toHex());
}

bool ContentCatalog::validate(const QByteArray &manifestBytes, const QByteArray &catalogBytes, QString &error)
{
    const auto manifest = QJsonDocument::fromJson(manifestBytes).object();
    const auto catalog = QJsonDocument::fromJson(catalogBytes).object();
    const auto archive = manifest.value(QStringLiteral("quarterly")).toObject();
    const QUrl url(archive.value(QStringLiteral("url")).toString());
    const QString digest = manifest.value(QStringLiteral("catalog")).toObject().value(QStringLiteral("sha256")).toString();
    const auto entries = catalog.value(QStringLiteral("stigs")).toArray();
    const double size = archive.value(QStringLiteral("size")).toDouble();
    bool valid = manifest.value(QStringLiteral("schema_version")).toDouble() == 1 &&
        catalog.value(QStringLiteral("schema_version")).toDouble() == 1 && !catalogName(manifest).isEmpty() &&
        QCryptographicHash::hash(catalogBytes, QCryptographicHash::Sha256).toHex() == digest.toLatin1() &&
        url.scheme() == QStringLiteral("https") && url.host() == QStringLiteral("dl.dod.cyber.mil") && url.userInfo().isEmpty() &&
        digestValid(archive.value(QStringLiteral("sha256")).toString()) && size > 0 && size <= 2LL * 1024 * 1024 * 1024 &&
        QDateTime::fromString(manifest.value(QStringLiteral("updated_at")).toString(), Qt::ISODate).isValid() && !entries.isEmpty();
    QSet<QString> identities;
    for (const auto &item : entries) {
        const auto entry = item.toObject();
        const QString identity = QString::fromUtf8(QJsonDocument(QJsonArray{entry.value(QStringLiteral("title")), entry.value(QStringLiteral("version")), entry.value(QStringLiteral("release"))}).toJson(QJsonDocument::Compact));
        valid = valid && !entry.value(QStringLiteral("title")).toString().isEmpty() &&
            !entry.value(QStringLiteral("release")).toString().isEmpty() && entry.value(QStringLiteral("version")).toInt() > 0 &&
            !entry.value(QStringLiteral("archive_member")).toString().isEmpty() && !identities.contains(identity) &&
            entry.value(QStringLiteral("url")) == archive.value(QStringLiteral("url")) &&
            entry.value(QStringLiteral("sha256")) == archive.value(QStringLiteral("sha256"));
        identities.insert(identity);
    }
    if (!valid) {
        error = QStringLiteral("The STIG catalog is invalid or unsupported. Import a local STIG ZIP or try again later.");
        return false;
    }
    _manifest = manifest;
    _catalog = catalog;
    error.clear();
    return true;
}

bool ContentCatalog::load(QString &error)
{
    const QUrl metadata = _site.resolved(QUrl(QStringLiteral("metadata/v1/")));
    const auto manifest = Downloads::fetch(metadata.resolved(QUrl(QStringLiteral("content.json"))), nullptr, 1024 * 1024, 15000);
    if (manifest.ok) {
        const auto name = catalogName(QJsonDocument::fromJson(manifest.data).object());
        if (!name.isEmpty()) {
            auto bytes = read(_cache + '/' + name);
            const QString digest = QJsonDocument::fromJson(manifest.data).object().value(QStringLiteral("catalog")).toObject().value(QStringLiteral("sha256")).toString();
            if (bytes.isEmpty() || QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex() != digest.toLatin1()) {
                const auto response = Downloads::fetch(metadata.resolved(QUrl(name)), nullptr, 32 * 1024 * 1024, 15000);
                if (response.ok) bytes = response.data;
            }
            if (validate(manifest.data, bytes, error)) {
                _cached = false;
                // Commit the pointer only after its immutable catalog has been saved.
                if (QDir().mkpath(_cache) && save(_cache + '/' + name, bytes))
                    save(_cache + QStringLiteral("/content.json"), manifest.data);
                return true;
            }
        }
    }
    const auto savedManifest = read(_cache + QStringLiteral("/content.json"));
    const auto savedName = catalogName(QJsonDocument::fromJson(savedManifest).object());
    if (!savedName.isEmpty() && validate(savedManifest, read(_cache + '/' + savedName), error)) {
        _cached = true;
        return true;
    }
    error = QStringLiteral("Unable to load a verified STIG catalog. Import the required STIG ZIP manually, then retry.");
    return false;
}

ContentCatalog::Archive ContentCatalog::quarterly() const
{
    const auto archive = _manifest.value(QStringLiteral("quarterly")).toObject();
    return {QUrl(archive.value(QStringLiteral("url")).toString()), archive.value(QStringLiteral("sha256")).toString().toLatin1(),
            static_cast<qint64>(archive.value(QStringLiteral("size")).toDouble()), {}};
}

bool ContentCatalog::find(const QString &title, int version, const QString &release, Archive &archive, QString &error) const
{
    for (const auto &value : _catalog.value(QStringLiteral("stigs")).toArray()) {
        const auto entry = value.toObject();
        if (entry.value(QStringLiteral("title")).toString() == title && entry.value(QStringLiteral("version")).toInt() == version &&
            entry.value(QStringLiteral("release")).toString() == release) {
            archive = quarterly();
            archive.member = entry.value(QStringLiteral("archive_member")).toString();
            error.clear();
            return true;
        }
    }
    error = QStringLiteral("This exact STIG version/release is not in the public catalog. Import its ZIP manually.");
    return false;
}

QString ContentCatalog::sourceDescription() const
{
    return QStringLiteral("%1STIG catalog from %2").arg(_cached ? QStringLiteral("Cached ") : QString(),
        _manifest.value(QStringLiteral("updated_at")).toString());
}

bool ContentCatalog::isDefaultQuarterly(const QUrl &url)
{
    return (url.host() == QStringLiteral("www.stigqter.com") || url.host() == QStringLiteral("stigqter.com")) &&
           url.path() == QStringLiteral("/stig.php") && url.query().isEmpty() &&
           (url.scheme() == QStringLiteral("https") || url.scheme() == QStringLiteral("http"));
}

bool ContentCatalog::download(const Archive &archive, QFile *destination, QString &error)
{
    if (!_archive || _archiveDigest != archive.sha256 || _archive->size() != archive.size) {
        auto candidate = std::make_unique<QTemporaryFile>();
        if (!candidate->open() || !DownloadFile(archive.url, candidate.get())) {
            error = QStringLiteral("Unable to download the STIG archive.");
            return false;
        }
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (candidate->size() != archive.size || !hash.addData(candidate.get()) || hash.result().toHex() != archive.sha256) {
            error = QStringLiteral("The STIG archive failed its size or SHA-256 check.");
            return false;
        }
        // Reuse one verified archive within this operation, then remove it when
        // the catalog is destroyed. A failed replacement retains the good copy.
        _archive = std::move(candidate);
        _archiveDigest = archive.sha256;
    }
    QTemporaryFile member;
    QString source = _archive->fileName();
    if (!archive.member.isEmpty()) {
        const auto files = GetFilesFromZip(source, archive.member);
        const auto found = files.constFind(archive.member);
        if (found == files.constEnd() || found->isEmpty() || !member.open() || member.write(*found) != found->size() || !member.flush()) {
            error = QStringLiteral("The requested STIG is missing from the archive.");
            return false;
        }
        source = member.fileName();
    }
    if (!DownloadFile(QUrl::fromLocalFile(source), destination)) {
        error = QStringLiteral("Unable to write the verified STIG archive.");
        return false;
    }
    error.clear();
    return true;
}
