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

#include "stigcheck.h"

#include <QString>

QString PrintSTIGCheck(STIGCheck s)
{
    return QString::number(s.id);
}

STIGCheck::STIGCheck() : QObject()
{

}

STIGCheck::STIGCheck(const STIGCheck &right) : STIGCheck()
{
    *this = right;
}

STIGCheck& STIGCheck::operator=(const STIGCheck &right)
{
    if (this != &right)
    {
        id = right.id;
        stig.SetValues(right.stig, false);
        cci = right.cci;
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
    }
    return *this;
}

STIGCheck::~STIGCheck()
{

}

Severity GetSeverity(QString severity)
{
    Severity ret = Severity::low;
    if (severity.startsWith("medium", Qt::CaseInsensitive))
        ret = Severity::medium;
    else if (severity.startsWith("high", Qt::CaseInsensitive))
        ret = Severity::high;
    return ret;
}
