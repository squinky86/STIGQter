// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "releasemetadata.h"
#include <QFile>
#include <QJsonObject>
#include <QTemporaryFile>
#include <memory>

class ContentCatalog {
public:
    struct Archive {
        QUrl url;
        QByteArray sha256;
        qint64 size = 0;
        QString member;
    };
    explicit ContentCatalog(const QUrl &site = ReleaseMetadata::siteUrl(), const QString &cache = QString());
    bool load(QString &error);
    Archive quarterly() const;
    bool find(const QString &title, int version, const QString &release, Archive &archive, QString &error) const;
    QString sourceDescription() const;
    static bool isDefaultQuarterly(const QUrl &url);
    bool download(const Archive &archive, QFile *destination, QString &error);

private:
    QUrl _site;
    QString _cache;
    QJsonObject _manifest;
    QJsonObject _catalog;
    bool _cached = false;
    std::unique_ptr<QTemporaryFile> _archive;
    QByteArray _archiveDigest;
    bool validate(const QByteArray &manifest, const QByteArray &catalog, QString &error);
};
