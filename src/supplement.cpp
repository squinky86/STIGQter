/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2020 Jon Hood, http://www.hoodsecurity.com/
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

#include "dbmanager.h"
#include "supplement.h"

/**
 * @class Supplement
 * @brief A @a STIG may contain several files as supplementary material. These
 * supplements are used to verify accountability, distribute metafiles, and
 * assist in the implementation of STIGs.
 */

/**
 * @brief Supplement::Supplement
 * @param right
 * Copy Constructor
 */
Supplement::Supplement(const Supplement &right) : Supplement(right.parent())
{
    *this = right;
}

/**
 * @brief Supplement::Supplement
 * @param parent
 *
 * Default constructor.
 */
Supplement::Supplement(QObject *parent) : QObject(parent),
    id(-1),
    STIGId(-1),
    path(),
    contents()
{
}

/**
 * @brief Supplement::GetSTIG
 * @return The @a STIG associated with this @a Supplement.
 */
STIG Supplement::GetSTIG()
{
    DbManager db;
    return db.GetSTIG(STIGId);
}

/**
 * @brief Supplement::operator =
 * @param right
 * @return This supplement assigned to from the right operand.
 */
Supplement &Supplement::operator=(const Supplement &right)
{
    if (this != &right)
    {
        id = right.id;
        STIGId = right.STIGId;
        path = right.path;
        contents = right.contents;
    }
    return *this;
}

/**
 * @brief PrintSupplement
 * @param supplement
 * @return string representing the supplement's identifier
 */
QString PrintSupplement(const Supplement &supplement)
{
    return supplement.path;
}
