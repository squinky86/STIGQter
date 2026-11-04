// SPDX-License-Identifier: GPL-3.0-or-later
#include "workerxccdf.h"
#include "dbmanager.h"
#include "xccdfresults.h"
#include <QFile>
#include <QFileInfo>

void WorkerXccdf::process()
{
    Worker::process();
    DbManager db;
    Q_EMIT initialize(_files.size(), 0);
    int count = 0;
    for (const auto &name : _files) {
        if (QThread::currentThread()->isInterruptionRequested()) break;
        Q_EMIT updateStatus(QStringLiteral("Importing XCCDF results: %1").arg(QFileInfo(name).fileName()));
        QFile file(name);
        XccdfResults results;
        QString error;
        QStringList missing;
        if (!file.open(QIODevice::ReadOnly)) error = file.errorString();
        else if (ParseXccdfResults(&file, results, error) &&
                 db.ApplyXccdfResults(_assetId, results, QFileInfo(name).fileName(), missing, error)) {
            Q_EMIT assetUpdated();
            if (!missing.isEmpty())
                Q_EMIT ThrowWarning(QStringLiteral("Unable to find checks"), missing.join(QStringLiteral(", ")));
        }
        if (!error.isEmpty()) Q_EMIT ThrowWarning(QStringLiteral("XCCDF import failed"), name + QStringLiteral(": ") + error);
        Q_EMIT progress(++count);
    }
    Q_EMIT finished();
}
