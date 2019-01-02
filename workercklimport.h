/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2019 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERCKLIMPORT_H
#define WORKERCKLIMPORT_H

#include "asset.h"

#include <QThread>

class WorkerCKLImport : public QObject
{
    Q_OBJECT

protected:
    QStringList _fileNames;
    void ParseCKL(QString fileName);
    Asset CheckAsset(Asset &a);

public:
    explicit WorkerCKLImport(QObject *parent = nullptr);
    void AddCKLs(QStringList ckls);

public slots:
    void process();

signals:
    void initialize(int, int);
    void progress(int);
    void updateStatus(QString);
    void finished();
};

#endif // WORKERCKLIMPORT_H
