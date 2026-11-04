/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2024–2026 Jon Hood, http://www.hoodsecurity.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "checklistwriter.h"
#include <QSaveFile>
#include "dbmanager.h"
#include "workercklb.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

/**
 * @class WorkerCKLB
 * @brief Export a STIG Viewer 3-compatible CKLB (JSON) file for an @a Asset.
 *
 * The CKLB format is the JSON-based checklist format introduced by STIG
 * Viewer 3. It carries the same compliance data as the legacy CKL XML
 * format but uses a JSON envelope understood by STIG Viewer 3 and newer
 * eMASS integrations.
 */

WorkerCKLB::WorkerCKLB(QObject *parent) : Worker(parent)
{
}

void WorkerCKLB::AddAsset(const Asset &asset, const QVector<STIG> &stigs)
{
    _asset = asset;
    AddSTIGs(stigs.isEmpty() ? asset.GetSTIGs() : stigs);
}

void WorkerCKLB::AddSTIGs(const QVector<STIG> &stigs)
{
    _stigs.append(stigs.toList());
}

void WorkerCKLB::AddFilename(const QString &name)
{
    _fileName = name;
}

void WorkerCKLB::process()
{
    Worker::process();
    Q_EMIT initialize(_stigs.count() + 1, 0);
    Q_EMIT updateStatus(QStringLiteral("Writing CKLB file…"));
    QSaveFile file(_fileName);
    const auto notify = [this](int step, const QString &status) {
        if (!status.isEmpty()) Q_EMIT updateStatus(status);
        if (step) Q_EMIT progress(step);
    };
    if (!file.open(QIODevice::WriteOnly) || !WriteCklb(&file, _asset, _stigs, notify) || !file.commit()) {
        Q_EMIT ThrowWarning(QStringLiteral("Checklist export failed"), QStringLiteral("Unable to write %1: %2").arg(_fileName, file.errorString()));
    } else {
        DbManager db;
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(_fileName).absolutePath());
        Q_EMIT updateStatus(QStringLiteral("Done!"));
    }
    Q_EMIT finished();
}
