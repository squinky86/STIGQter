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

#include "control.h"
#include "dbmanager.h"

/**
 * @class Control
 * @brief A @a Control corresponds to a particular RMF checklist
 * grouping of assessment procedures. The RMF hierarchy consists of
 * @a Family → @a Control → @a CCI.
 *
 * A @a Control is the base unit of RMF by which assessment scoring
 * takes place. Risk calculations roll up and are reported at the
 * @a Control level to provide management with a high-level overview
 * of the security posture of a system.
 *
 * Selection of applicable controls is performed by baselining and
 * tailoring the system's capabilities and security needs.
 */

/**
 * @brief Control::Control
 * @param parent
 *
 * Default constructor.
 */
Control::Control(QObject *parent) : QObject(parent),
    id(-1),
    familyId(-1),
    number(0),
    enhancement(),
    title(),
    description(),
    importSeverity(),
    importRelevanceOfThreat(),
    importLikelihood(),
    importImpact(),
    importImpactDescription(),
    importResidualRiskLevel(),
    importRecommendations()
{
}

/**
 * @brief Control::Control
 * @param right
 *
 * Copy constructor.
 */
Control::Control(const Control &right) : Control(right.parent())
{
    *this = right;
}

/**
 * @brief Control::GetFamily
 * @return The @a Family associated with this @a Control
 */
Family Control::GetFamily() const
{
    DbManager db;
    return db.GetFamily(familyId);
}

QVector<CCI> Control::GetCCIs() const
{
    DbManager db;
    return db.GetCCIs(*this);
}

/**
 * @brief Control::operator=
 * @param right
 * @return This @a Control, copied from the assignee.
 *
 * Deep copy assignment operator.
 */
Control& Control::operator=(const Control &right)
{
    if (this != &right)
    {
        id = right.id;
        familyId = right.familyId;
        number = right.number;
        enhancement = right.enhancement;
        title = right.title;
        description = right.description;
	importSeverity = right.importSeverity;
	importRelevanceOfThreat = right.importRelevanceOfThreat;
	importLikelihood = right.importLikelihood;
	importImpact = right.importImpact;
	importImpactDescription = right.importImpactDescription;
	importResidualRiskLevel = right.importResidualRiskLevel;
	importRecommendations = right.importRecommendations;
    }
    return *this;
}

/**
 * @brief Control::IsImport
 * @return @c True when a CCI has been imported under this control.
 * Otherwise, @c false.
 */
bool Control::IsImport() const
{
    Q_FOREACH (auto cci, GetCCIs())
    {
        if (cci.isImport)
            return true;
    }
    return false;
}

/**
 * @brief Control::operator==
 * @param right
 * @return @c True when the @a Control entities refer to the same
 * @a Control. Otherwise, @c false.
 */
bool operator==(Control const& lhs, Control const& rhs)
{
    return (PrintControl(lhs).compare(PrintControl(rhs), Qt::CaseInsensitive) == 0);
}

/**
 * @brief PrintControl
 * @param control
 * @return Human-readable @a Control
 */
[[nodiscard]] QString PrintControl(const Control &control)
{
    QString ret = control.GetFamily().acronym + "-" + QString::number(control.number);
    if (control.enhancement > 0)
        ret.append("(" + QString::number(control.enhancement) + ")");
    return ret;
}
