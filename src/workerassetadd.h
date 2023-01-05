/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2023 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERASSETADD_H
#define WORKERASSETADD_H

#include "asset.h"
#include "stig.h"
#include "worker.h"

#include <QObject>

class WorkerAssetAdd : public Worker
{
    Q_OBJECT

private:
    Asset _toAdd;
    QList<STIG> _toMapSTIGs;

public:
    explicit WorkerAssetAdd(QObject *parent = nullptr);
    void AddAsset(const Asset &asset);
    void AddSTIG(const STIG &stig);

public Q_SLOTS:
    void process() override;
};

#endif // WORKERASSETADD_H
