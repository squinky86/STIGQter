/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020–2021 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKER_H
#define WORKER_H

class STIGQter;

#include <QThread>
#include <QString>

class Worker : public QObject
{
    Q_OBJECT

public:
    explicit Worker(QObject *parent = nullptr);
    ~Worker();
    virtual void process() = 0;
    [[nodiscard]] QThread* ConnectThreads(STIGQter *sq = nullptr);

Q_SIGNALS:
    void initialize(int, int);
    void progress(int);
    void updateStatus(QString);
    void finished();
    void ThrowWarning(QString title, QString message);
};

#endif // WORKER_H
