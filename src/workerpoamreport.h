/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2021 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERPOAMREPORT_H
#define WORKERPOAMREPORT_H

#include "worker.h"

#include <QObject>

class WorkerPOAMReport : public Worker
{
    Q_OBJECT

private:
    QString _fileName;
    bool _apNums;

public:
    explicit WorkerPOAMReport(QObject *parent = nullptr);
    void SetReportName(const QString &fileName);
    void SetAPNums(const bool apNums = false);

public Q_SLOTS:
    void process() override;
};

#endif // WORKERPOAMREPORT_H
