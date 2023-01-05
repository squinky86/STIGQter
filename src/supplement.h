/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020–2023 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef SUPPLEMENT_H
#define SUPPLEMENT_H

#include "stig.h"

#include <QObject>

class Supplement : public QObject
{
    Q_OBJECT
public:
    Supplement(const Supplement &right);
    explicit Supplement(QObject *parent = nullptr);
    ~Supplement() override = default;

    int id;
    int STIGId;
    QString path;
    QByteArray contents;
    STIG GetSTIG();
    Supplement& operator=(const Supplement &right);
};

Q_DECLARE_METATYPE(Supplement);

[[nodiscard]] QString PrintSupplement(const Supplement &supplement);

#endif // SUPPLEMENT_H
