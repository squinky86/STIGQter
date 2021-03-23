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

#ifndef FAMILY_H
#define FAMILY_H

#include <QObject>
#include <QString>

class Family : public QObject
{
    Q_OBJECT
public:
    Family(const Family &right);
    explicit Family(QObject *parent = nullptr);
    ~Family() override = default;
    int id;
    QString acronym;
    QString description;
    Family& operator=(const Family &right);
};

Q_DECLARE_METATYPE(Family);

[[nodiscard]] QString PrintFamily(const Family &family);

#endif // FAMILY_H
