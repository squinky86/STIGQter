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

#ifndef CONTROL_H
#define CONTROL_H

#include "family.h"

#include <QObject>
#include <QString>

class Control : public QObject
{
    Q_OBJECT
public:
    Control(const Control &right);
    Control(QObject *parent = nullptr);
    int id;
    int familyId;
    Family Family();
    int number;
    int enhancement;
    QString title;
    Control& operator=(const Control &right);
};

Q_DECLARE_METATYPE(Control);

QString PrintControl(Control c);

#endif // CONTROL_H
