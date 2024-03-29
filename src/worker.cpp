/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020–2023 Jon Hood, http://www.hoodsecurity.com/
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

#include <QApplication>
#include <QThread>

/**
 * @class Worker
 * @brief Base abstract class for thread workers
 */

/**
 * @brief Worker::Worker
 * @param parent
 *
 * Default constructor.
 */
Worker::Worker(QObject *parent) : QObject(parent), _threadId(QString())
{
}

void Worker::process()
{
    _threadId = QString::number(reinterpret_cast<quint64>(QThread::currentThreadId()));
}

/**
 * @brief Worker::ConnectThreads
 * @param sq
 * @param blocking
 *
 * Connect the signals and slots and move the worker to the supplied thread.
 *
 * Returns the new QThread that the worker is attached to. It is up to the
 * calling entity to clean up the thread.
 */
[[nodiscard]] QThread* Worker::ConnectThreads(STIGQter *sq, bool blocking)
{
    QThread *thread = new QThread();
    this->moveToThread(thread);
    connect(thread, SIGNAL(started()), this, SLOT(process()));
    connect(this, SIGNAL(finished()), thread, SLOT(quit()));
    if (sq)
    {
        //check if this is a blocking thread
        if (blocking)
        {
            connect(thread, SIGNAL(finished()), sq, SLOT(CompletedThread()));
            connect(this, SIGNAL(initialize(int, int)), sq, SLOT(Initialize(int, int)));
            connect(this, SIGNAL(progress(int)), sq, SLOT(Progress(int)));
            connect(this, SIGNAL(updateStatus(QString)), sq, SLOT(StatusChange(QString)));
        }
        else
        {
            connect(thread, SIGNAL(finished()), sq, SLOT(CompletedThreadUnblocked()));
        }
        connect(this, SIGNAL(ThrowWarning(QString, QString)), sq, SLOT(ShowMessage(QString, QString)));
    }
    return thread;
}

/**
 * @brief Worker::GetThreadId
 * @return the thread id of the previously attached thread
 */
QString Worker::GetThreadId()
{
    return _threadId;
}
