/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2022 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERCKLUPGRADE_H
#define WORKERCKLUPGRADE_H

#include "asset.h"
#include "worker.h"

#include <QObject>

class WorkerCKLUpgrade : public Worker
{
    Q_OBJECT

private:
    Asset _asset;
    STIG _stig;

public:
    explicit WorkerCKLUpgrade(QObject *parent = nullptr);
    void AddSTIG(const Asset &asset, const STIG &stig);

public Q_SLOTS:
    void process() override;
};

#endif // WORKERCKLUPGRADE_H
