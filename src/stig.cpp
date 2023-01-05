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

#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"

/**
 * @class STIG
 * @brief A @a STIG is a Security Technical Implementation Guide.
 * Each @a STIG details a set of @a STIGChecks which can be used to
 * help the security posture of an @a Asset.
 *
 * The Defense Information Systems Agency (DISA) has been tasked
 * with issuing official STIG guidance. This duty has been one of
 * the Information Assurance Support Environment's (IASE) main
 * missions for DISA, and has now been moved to the public cyber.mil
 * portal.
 *
 * STIGs can be downloaded publicly from @l {https://public.cyber.mil/}.
 * Some STIGs are only provided at the FOUO level and require
 * government authentication to access them. Others are fully
 * unclassified, and though they have no markings that they are clear
 * for public release, are distributed freely over the internet from
 * the public public.cyber.mil portal. Only the freely available,
 * public STIGs are supported in STIGQter.
 *
 * A @a STIG is composed of @a STIGChecks. These @a STIGChecks are
 * then mapped against @a CCIs. The hierarchy is:
 * @a STIG → @a STIGCheck   ↴
 * @a Family → @a Control → @a CCI.
 */

/**
 * @brief STIG::STIG
 * @param parent
 *
 * Default constructor.
 */
STIG::STIG(QObject *parent) : QObject(parent),
    id(-1),
    title(),
    description(),
    release(),
    version(0),
    benchmarkId(),
    fileName()
{
}

/**
 * @brief STIG::GetSTIGChecks
 * @return The list of @a STIGChecks associated with this @a STIG.
 */
QVector<STIGCheck> STIG::GetSTIGChecks() const
{
    DbManager db;
    return db.GetSTIGChecks(*this);
}

/**
 * @brief STIG::GetSupplements
 * @return The list of @a Supplements associated with this @a STIG.
 */
QVector<Supplement> STIG::GetSupplements() const
{
    DbManager db;
    return db.GetSupplements(*this);
}

/**
 * @brief STIG::GetAssets
 * @return The list of @a Assets that use this @a STIG.
 */
QVector<Asset> STIG::GetAssets() const
{
    DbManager db;
    return db.GetAssets(*this);
}

/**
 * @brief STIG::STIG
 * @param right
 *
 * Copy constructor.
 */
STIG::STIG(const STIG &right) : STIG(right.parent())
{
    *this = right;
}

/**
 * @brief STIG::operator=
 * @param right
 * @return This @a STIG, copied from the assignee.
 *
 * Deep copy assignment operator.
 */
STIG &STIG::operator=(const STIG &right)
{
    if (this != &right)
    {
        id = right.id;
        title = right.title;
        description = right.description;
        release = right.release;
        version = right.version;
        benchmarkId = right.benchmarkId;
        fileName = right.fileName;
    }
    return *this;
}

/**
 * @brief STIG::operator==
 * @param right
 * @return @c True when the @a STIG entities refer to the same
 * @a STIG. Otherwise, @c false.
 *
 * If the @a STIG @a id is the same between the comparates, they
 * are assumed to be equivalent. If not, the @a title, @a release,
 * and @a version form a unique key to test equivalence with.
 */
bool operator==(STIG const& lhs, STIG const& rhs)
{
    if ((lhs.id <= 0) || (rhs.id <= 0))
    {
        return ((lhs.title == rhs.title) &&
                // (description == right.description) && // description is irrelevant to a STIG being the same; the version numbers are what matter!
                (lhs.release == rhs.release) &&
                (lhs.version == rhs.version));
    }
    return lhs.id == rhs.id;
}

/**
 * @brief STIG::operator!=
 * @param right
 * @return @c True when the @a STIG entities refer to different
 * @a STIGs. Otherwise, @c false.
 *
 * If the @a STIG @a id is the same between the comparates, they
 * are assumed to be equivalent. If not, the @a title, @a release,
 * and @a version form a unique key to test equivalence with.
 */
bool operator!=(STIG const& lhs, STIG const& rhs)
{
    return !(lhs == rhs);
}

/**
 * @brief STIG::operator <
 * @param right
 * @return @c True when this STIG is less than the provided operator.
 * Otherwise, @c false.
 */
bool STIG::operator<(const STIG &right) const
{
    if (title == right.title)
    {
        if (version == right.version)
        {
            return release < right.release;
        }
        return version < right.version;
    }
    return title < right.title;
}

/**
 * @brief PrintSTIG
 * @param stig
 * @return A human-readable @a STIG representation.
 */
[[nodiscard]] QString PrintSTIG(const STIG &stig)
{
    return stig.title + " Version: " + QString::number(stig.version) + " " + stig.release;
}
