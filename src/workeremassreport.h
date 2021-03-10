/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019–2021 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKEREMASSREPORT_H
#define WORKEREMASSREPORT_H

#include "worker.h"

#include <QObject>

class WorkerEMASSReport : public Worker
{
    Q_OBJECT

private:
    QString _fileName;
    qint64 DateChooser(bool isImport, qint64 curDate, const QString &importDate, bool useCurDate);

public:
    explicit WorkerEMASSReport(QObject *parent = nullptr);
    void SetReportName(const QString &fileName);

public Q_SLOTS:
    void process() override;
};

#endif // WORKEREMASSREPORT_H
