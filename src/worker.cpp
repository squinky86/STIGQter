/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020 Jon Hood, http://www.hoodsecurity.com/
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

#include "dbmanager.h"
#include "stigqter.h"
#include "worker.h"

#include <QThread>

/**
 * @class Worker
 * @brief Base abstract class for thread workers
 */

/**
 * @brief WorkerAssetAdd::WorkerAssetAdd
 * @param parent
 *
 * Default constructor.
 */
Worker::Worker(QObject *parent) : QObject(parent)
{
}

/**
 * @brief Worker::ConnectThreads
 * @param thread
 * @param sq
 *
 * Connect the signals and slots and move the worker to the supplied thread.
 */
[[nodiscard]] QThread* Worker::ConnectThreads(STIGQter *sq)
{
    QThread *thread = new QThread();
    this->moveToThread(thread);
    connect(thread, SIGNAL(started()), this, SLOT(process()));
    connect(this, SIGNAL(finished()), thread, SLOT(quit()));
    if (sq)
    {
        connect(thread, SIGNAL(finished()), sq, SLOT(CompletedThread()));
        connect(this, SIGNAL(initialize(int, int)), sq, SLOT(Initialize(int, int)));
        connect(this, SIGNAL(progress(int)), sq, SLOT(Progress(int)));
        connect(this, SIGNAL(updateStatus(QString)), sq, SLOT(StatusChange(QString)));
        connect(this, SIGNAL(ThrowWarning(QString, QString)), sq, SLOT(ShowMessage(QString, QString)));
    }
    return thread;
}
