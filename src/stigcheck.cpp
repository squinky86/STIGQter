/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2019 Jon Hood, http://www.hoodsecurity.com/
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

/**
 * @class STIGCheck
 * @brief A @a STIGCheck is an individual component of a @a STIG. A
 * @a STIG is composed of any number of @a STIGChecks and form a
 * security checklist for an applicable @a Asset.
 *
 * Most importantly, a @a STIGCheck details the overall risk
 * severity, non-compliance situations, and vulnerability information
 * related to an individual setting or check component for the
 * affected @a Asset. Mitigations and fixes are also presented to
 * bring the @a Asset into a compliant state.
 *
 * A @a STIG is composed of @a STIGChecks. These @a STIGChecks are
 * then mapped against @a CCIs. The hierarchy is:
 * @a STIG → @a STIGCheck   ↴
 * @a Family → @a Control → @a CCI.
 */

/**
 * @enum Severity
 *
 * A @a STIGCheck is associated with a general \a Severity level.
 * Severities have historically been mapped to a Category (CAT)
 * Level. It's important to remember that the default severity level
 * can be overridden for a particular @a Asset.
 *
 * @value high
 *        The check is a CAT I or HIGH severity.
 * @value medium
 *        The check is a CAT II or MODERATE severity.
 * @value low
 *        The check is a CAT III or LOW severity.
 * @value none
 *        The check is a CAT IV or NO severity. The term "CAT IV" is
 *        a misnomer and is not defined by any particular standard.
 *        It usually refers to an informational commentary on non-
 *        compliance rather than one that imparts any risk.
 */

/**
 * @brief STIGCheck::STIGCheck
 * @param parent
 *
 * Default constructor. An ID of -1 is used to represent a
 * @a STIGCheck that is detached from the database or incomplete.
 */
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
    iaControls(),
    targetKey()
{
}

/**
 * @brief STIGCheck::STIGCheck
 * @param right
 *
 * Copy constructor.
 */
STIGCheck::STIGCheck(const STIGCheck &right) : STIGCheck(right.parent())
{
    *this = right;
}

/**
 * @brief STIGCheck::operator =
 * @param right
 * @return This @a STIGCheck, copied from the assignee.
 *
 * Deep copy assignment operator.
 */
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
        targetKey = right.targetKey;
    }
    return *this;
}

/**
 * @brief STIGCheck::GetSTIG
 * @return The @a STIG associated with this @a STIGCheck.
 */
STIG STIGCheck::GetSTIG() const
{
    DbManager db;
    return db.GetSTIG(stigId);
}

/**
 * @brief STIGCheck::GetCCI
 * @return The @a CCI associated with this @a STIGCheck.
 */
CCI STIGCheck::GetCCI() const
{
    DbManager db;
    return db.GetCCI(cciId);
}

/**
 * @brief GetSeverity
 * @param severity
 * @return Converts the @a severity string to a value defined in the
 * @a Severity enum.
 */
Severity GetSeverity(const QString &severity)
{
    QString toCheck = severity;
    if (toCheck.startsWith(QStringLiteral("I")))
        toCheck = QStringLiteral("CAT ") + toCheck;
    if (toCheck.isEmpty() || toCheck.endsWith(QStringLiteral(" IV")))
        return Severity::none;
    if (toCheck.startsWith(QStringLiteral("medium"), Qt::CaseInsensitive) || toCheck.endsWith(QStringLiteral(" II")))
        return Severity::medium;
    if (toCheck.startsWith(QStringLiteral("high"), Qt::CaseInsensitive) || toCheck.endsWith(QStringLiteral(" I")))
        return Severity::high;
    return Severity::low;
}

/**
 * @brief GetSeverity
 * @param severity
 * @param cat
 * @return When @a cat is @c true, returns a human-readable Category
 * level for the supplied @a severity. Otherwise, returns a human-
 * readable general severity rank.
 */
QString GetSeverity(Severity severity, bool cat)
{
    switch (severity)
    {
    case Severity::high:
        return cat ? QStringLiteral("CAT I") : QStringLiteral("high");
    case Severity::medium:
        return cat ? QStringLiteral("CAT II") : QStringLiteral("medium");
    case Severity::low:
        return cat ? QStringLiteral("CAT III") : QStringLiteral("low");
    default:
        return cat ? QStringLiteral("CAT IV") : QString();
    }
}

/**
 * @brief PrintSTIGCheck
 * @param stigCheck
 * @return A human-readable @a STIGCheck representation.
 */
QString PrintSTIGCheck(const STIGCheck &stigCheck)
{
    return stigCheck.rule;
}

/**
 * @brief PrintCMRSVulnId
 * @param stigCheck
 * @return CMRS-formatted V-ID
 */
QString PrintCMRSVulnId(const STIGCheck &stigCheck)
{
    QString ret = stigCheck.vulnNum;
    if (ret.startsWith(QStringLiteral("V-")))
    {
        ret = ret.remove(1, 1);
        while (ret.length() < 8)
            ret = ret.insert(1, '0');
    }
    return ret;
}
