/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2021 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERSTIGADD_H
#define WORKERSTIGADD_H

#include "worker.h"

#include <QObject>

class WorkerSTIGAdd : public Worker
{
    Q_OBJECT

private:
    QStringList _todo;
    bool _enableSupplements;
    void ParseSTIG(const QByteArray &stig, const QString &fileName, const QMap<QString, QByteArray> &supplements);

public:
    explicit WorkerSTIGAdd(QObject *parent = nullptr);
    void AddSTIGs(const QStringList &stigs);
    void SetEnableSupplements(bool enableSupplements);

public Q_SLOTS:
    void process() override;
};

#endif // WORKERSTIGADD_H
