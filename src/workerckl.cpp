/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2021–2023 Jon Hood, http://www.hoodsecurity.com/
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
#include "workerckl.h"

#include <QFile>
#include <QFileInfo>
#include <QUuid>
#include <QXmlStreamReader>

#include <functional>

/**
 * @class WorkerCKL
 * @brief When generating an asset's CKL file, multiple STIG checklists can be
 * used to comprise it. Traditionally, CKL files are used to store a single
 * asset's individual test results for one STIG; however, the format supports
 * multiple checklists.
 *
 * To generate the individual STIGs mapping single assets to single STIG
 * checklists, use the Reports → STIG CKLs export.
 */

/**
 * @brief WorkerCKL::WorkerCKL
 * @param parent
 *
 * Default Constructor
 */
WorkerCKL::WorkerCKL(QObject *parent) : Worker(parent)
{
}

/**
 * @brief WorkerCKL::AddAsset
 * @param asset
 * @param stigs
 *
 * The asset to operate on and an optional set of STIGs
 */
void WorkerCKL::AddAsset(const Asset &asset, const QVector<STIG> &stigs)
{
    _asset = asset;
    if (stigs.isEmpty())
    {
        AddSTIGs(asset.GetSTIGs());
    }
    else
    {
        AddSTIGs(stigs);
    }
}

/**
 * @brief WorkerCKL::AddSTIGs
 * @param stigs
 *
 * List of STIGs to use with CKL file
 */
void WorkerCKL::AddSTIGs(const QVector<STIG> &stigs)
{
    _stigs.append(stigs.toList());
}

/**
 * @brief WorkerCKL::AddFilename
 * @param name
 *
 * The checklist will be written to this supplied filename.
 */
void WorkerCKL::AddFilename(const QString &name)
{
    _fileName = name;
}

/**
 * @brief WorkerCKL::process
 *
 * Perform the operations of this worker process.
 *
 * @example process
 * @title process
 *
 * This function should be kicked off as a background task. It emits
 * signals that describe its progress and state.
 *
 * @code
 * QThread *thread = new QThread;
 * WorkerCKL *ckl = new WorkerCKL();
 * ckl->moveToThread(thread); // move the worker to the new thread
 * ckl->AddFilename(fileName); // "fileName" is a QString with the path to where the CKL file should be exported.
 * connect(thread, SIGNAL(started()), ckl, SLOT(process())); // Start the worker when the new thread emits its started() signal.
 * connect(ckl, SIGNAL(finished()), thread, SLOT(quit())); // Kill the thread once the worker emits its finished() signal.
 * connect(thread, SIGNAL(finished()), this, SLOT(EndFunction()));  // execute some EndFunction() (custom code) when the thread is cleaned up.
 * connect(ckl, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int))); // If progress status is needed, connect a custom Initialize(int, int) function to the initialize slot.
 * connect(ckl, SIGNAL(progress(int)), this, SLOT(Progress(int))); // If progress status is needed, connect the progress slot to a custom Progress(int) function.
 * connect(ckl, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString))); // If progress status is needed, connect a human-readable display of the status to the updateStatus(QString) slot.
 * t->start(); // Start the thread
 *
 * //Don't forget to handle the *thread and *addAsset cleanup!
 * @endcode
 */
void WorkerCKL::process()
{
    Worker::process();
    Q_EMIT initialize(_stigs.count() + 1, 0);
    Q_EMIT updateStatus(QStringLiteral("Writing CKL file…"));
    QSaveFile file(_fileName);
    const auto notify = [this](int step, const QString &status) {
        if (!status.isEmpty()) Q_EMIT updateStatus(status);
        if (step) Q_EMIT progress(step);
    };
    if (!file.open(QIODevice::WriteOnly) || !WriteCkl(&file, _asset, _stigs, notify) || !file.commit()) {
        Q_EMIT ThrowWarning(QStringLiteral("Checklist export failed"), QStringLiteral("Unable to write %1: %2").arg(_fileName, file.errorString()));
    } else {
        DbManager db;
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(_fileName).absolutePath());
        Q_EMIT updateStatus(QStringLiteral("Done!"));
    }
    Q_EMIT finished();
}
