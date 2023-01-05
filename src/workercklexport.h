/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019–2023 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERCKLEXPORT_H
#define WORKERCKLEXPORT_H

#include "worker.h"

#include <QObject>

class WorkerCKLExport : public Worker
{
    Q_OBJECT

private:
    QString _dirName;
    QString _assetName;
    bool _monolithic;

public:
    explicit WorkerCKLExport(QObject *parent = nullptr);
    void SetAssetName(const QString &assetName);
    void SetExportDir(const QString &dir);
    void SetMonolithic(const bool monolithic);

public Q_SLOTS:
    void process() override;
};

#endif // WORKERCKLEXPORT_H
