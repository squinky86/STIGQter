/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019–2022 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef WORKERHTML_H
#define WORKERHTML_H

#include "worker.h"

#include <QObject>

class WorkerHTML : public Worker
{
    Q_OBJECT

private:
    QString _exportDir;
    QString CheckItem(const QString &title, const QString &contents);
    QString CheckItem(const QString &title, const QStringList &contents);
    QString Sanitize(const QString &contents);

public:
    explicit WorkerHTML(QObject *parent = nullptr);
    void SetDir(const QString &dir);

public Q_SLOTS:
    void process() override;
};

#endif // WORKERHTML_H
