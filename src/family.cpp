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

#include "family.h"

/**
 * @class Family
 * @brief A @a Family corresponds to a particular RMF checklist
 * grouping of @a Controls. The RMF hierarchy consists of
 * @a Family → @a Control → @a CCI.
 *
 * A @a Family is the largest unit of RMF by which @a Controls are
 * grouped. Normally, systems divide documentation into separate
 * @a Families.
 *
 * The standard set of Families defined by NIST 800-53rev4 is
 * @list
 * @li AC - Access Control
 * @li AU - Audit and Accountability
 * @li AT - Awareness and Training
 * @li CM - Configuration Management
 * @li CP - Contingency Planning
 * @li IA - Identification and Authentication
 * @li IR - Incident Response
 * @li MA - Maintenance
 * @li MP - Media Protection
 * @li PS - Personnel Security
 * @li PE - Physical and Environmental Protection
 * @li PL - Planning
 * @li PM - Program Management
 * @li RA - Risk Assessment
 * @li CA - Security Assessment and Authorization
 * @li SC - System and Communications Protection
 * @li SI - System and Information Integrity
 * @li SA - System and Services Acquisition
 * @endlist
 *
 * A @a Family provides a high-level, logical grouping for
 * documentation, but the level is too high for conducting any risk
 * analyses. For risk determinations, the @a CCI level should report
 * the individual weaknesses for a system, and the @a Control level
 * should roll up the highest issues identified by the @a Control's
 * @a CCIs.
 */

/**
 * @brief Family::Family
 * @param parent
 *
 * Default constructor.
 */
Family::Family(QObject *parent) : QObject(parent),
    id(-1),
    acronym(QStringLiteral("ZZ")),
    description(QStringLiteral("Default Family"))
{
}

/**
 * @brief Family::Family
 * @param right
 *
 * Copy constructor.
 */
Family::Family(const Family &right) : Family(right.parent())
{
    *this = right;
}

/**
 * @brief Family::operator=
 * @param right
 * @return This @a Family, copied from the assignee.
 *
 * Deep copy assignment operator.
 */
Family& Family::operator=(const Family &right)
{
    if (this != &right)
    {
        id = right.id;
        acronym = right.acronym;
        description = right.description;
    }
    return *this;
}

/**
 * @brief PrintFamily
 * @param family
 * @return Human-readable @a Family
 */
QString PrintFamily(const Family &family)
{
    return family.acronym;
}
