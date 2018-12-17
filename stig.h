/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef STIG_H
#define STIG_H

#include <QList>
#include <QObject>
#include <QString>

class STIGCheck;

class STIG : public QObject
{
    Q_OBJECT
public:
    STIG(const STIG &right);
    STIG(QObject *parent = nullptr);

    int id;
    QString title;
    QString description;
    QString release;
    int version;
    QList<STIGCheck> STIGChecks() const;
    STIG& operator=(const STIG &right);
    bool operator==(const STIG &right);
};

Q_DECLARE_METATYPE(STIG);

QString PrintSTIG(STIG s);

#endif // STIG_H