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

#include "dbmanager.h"
#include "stigcheck.h"

#include <QString>

QString PrintSTIGCheck(STIGCheck s)
{
    return s.rule;
}

STIGCheck::STIGCheck(QObject *parent) : QObject(parent),
    id(-1),
    stigId(-1),
    cciId(-1),
    vulnNum(),
    groupTitle(),
    ruleVersion(),
    rule(),
    severity(Severity::high),
    weight(10.0),
    title(),
    vulnDiscussion(),
    falsePositives(),
    falseNegatives(),
    fix(),
    check(),
    documentable(false),
    mitigations(),
    severityOverrideGuidance(),
    checkContentRef(),
    potentialImpact(),
    thirdPartyTools(),
    mitigationControl(),
    responsibility(),
    iaControls()
{
}

STIGCheck::STIGCheck(const STIGCheck &right) : STIGCheck(right.parent())
{
    *this = right;
}

STIGCheck& STIGCheck::operator=(const STIGCheck &right)
{
    if (this != &right)
    {
        id = right.id;
        stigId = right.stigId;
        cciId = right.cciId;
        rule = right.rule;
        vulnNum = right.vulnNum;
        groupTitle = right.groupTitle;
        ruleVersion = right.ruleVersion;
        severity = right.severity;
        weight = right.weight;
        title = right.title;
        vulnDiscussion = right.vulnDiscussion;
        falsePositives = right.falsePositives;
        falseNegatives = right.falseNegatives;
        fix = right.fix;
        check = right.check;
        documentable = right.documentable;
        mitigations = right.mitigations;
        severityOverrideGuidance = right.severityOverrideGuidance;
        checkContentRef = right.checkContentRef;
        potentialImpact = right.potentialImpact;
        thirdPartyTools = right.thirdPartyTools;
        mitigationControl = right.mitigationControl;
        responsibility = right.responsibility;
        iaControls = right.iaControls;
    }
    return *this;
}

STIG STIGCheck::STIG()
{
    DbManager db;
    return db.GetSTIG(stigId);
}

CCI STIGCheck::CCI()
{
    DbManager db;
    return db.GetCCI(cciId);
}

Severity GetSeverity(const QString &severity)
{
    if (severity.isEmpty())
        return Severity::none;
    if (severity.startsWith("medium", Qt::CaseInsensitive))
        return Severity::medium;
    if (severity.startsWith("high", Qt::CaseInsensitive))
        return Severity::high;
    return Severity::low;
}
