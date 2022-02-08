/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2021–2022 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERCKL_H
#define WORKERCKL_H

#include "asset.h"
#include "stig.h"
#include "worker.h"

#include <QObject>
#include <QXmlStreamWriter>

class WorkerCKL : public Worker
{
    Q_OBJECT

private:
    QString _fileName;
    Asset _asset;
    QList<STIG> _stigs;
    void WriteXMLEntry(QXmlStreamWriter &stream, const QString &name, const QString &value);
    void AddSTIGs(const QVector<STIG> &stigs);

public:
    explicit WorkerCKL(QObject *parent = nullptr);
    void AddAsset(const Asset &asset, const QVector<STIG> &stigs = {});
    void AddFilename(const QString &name);

public Q_SLOTS:
    void process() override;
};

#endif // WORKERCKL_H
