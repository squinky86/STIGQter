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

#ifndef CONTROL_H
#define CONTROL_H

#include "family.h"

#include <QObject>
#include <QString>

class CCI;

class Control : public QObject
{
    Q_OBJECT
public:
    Control(const Control &right);
    explicit Control(QObject *parent = nullptr);
    ~Control() override = default;
    int id;
    int familyId;
    Family GetFamily() const;
    QVector<CCI> GetCCIs() const;
    int number;
    int enhancement;
    QString title;
    QString description;
    QString importSeverity;
    QString importRelevanceOfThreat;
    QString importLikelihood;
    QString importImpact;
    QString importImpactDescription;
    QString importResidualRiskLevel;
    QString importRecommendations;
    Control& operator=(const Control &right);
    friend bool operator<(const Control &left, const Control &right)
    {
        if (left.familyId == right.familyId)
        {
            if (left.number == right.number)
            {
                return left.enhancement < right.enhancement;
            }
            return left.number < right.number;
        }
        return left.GetFamily().acronym < right.GetFamily().acronym;
    }
    bool IsImport() const;
};

bool operator==(Control const& lhs, Control const& rhs);

Q_DECLARE_METATYPE(Control);

[[nodiscard]] QString PrintControl(const Control &control);

#endif // CONTROL_H
