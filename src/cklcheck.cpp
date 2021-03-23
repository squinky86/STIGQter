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

#include "cklcheck.h"
#include "dbmanager.h"

/**
 * @class CKLCheck
 * @brief A Checklist (CKL) Check represents the compliance @a Status
 * of an @a Asset's individual @a STIGCheck.
 *
 * The @a Severity of the check be overridden at the CKL level.
 */

/**
 * @enum Status
 *
 * A @a CKLCheck maps a @a STIGCheck to an @a Asset, and the
 * compliance state is stored as a @a Status.
 *
 * @value NotReviewed
 *        The check has not been reviewed.
 * @value Open
 *        The check is not compliant.
 * @value NotAFinding,
 *        The check is compliant.
 * @value NotApplicable
 *        The check is not applicable to the @a Asset.
 */

/**
 * @brief CKLCheck::CKLCheck
 * @param parent
 *
 * Default constructor.
 */
CKLCheck::CKLCheck(QObject *parent) : QObject(parent),
    id(-1),
    assetId(-1),
    stigCheckId(-1),
    status(Status::NotReviewed),
    findingDetails(),
    comments(),
    severityOverride(),
    severityJustification()
{
}

/**
 * @overload CKLCheck::CKLCheck(const CKLCheck &right)
 * @brief CKLCheck::CKLCheck
 * @param right
 *
 * Copy constructor.
 */
CKLCheck::CKLCheck(const CKLCheck &right) : CKLCheck(right.parent())
{
    *this = right;
}

/**
 * @brief CKLCheck::GetAsset
 * @return The @a Asset associated with this check.
 *
 * A check maps an @a Asset to a @a STIGCheck and stores its
 * compliance state. This function retrieves the associated
 * @a Asset.
 */
Asset CKLCheck::GetAsset() const
{
    DbManager db;
    return db.GetAsset(assetId);
}

/**
 * @brief CKLCheck::GetSTIGCheck
 * @return The @a STIGCheck associated with this check.
 *
 * A check maps an @a Asset to a @a STIGCheck and stores its
 * compliance state. This function retrieves the associated
 * @a STIGCheck.
 */
STIGCheck CKLCheck::GetSTIGCheck() const
{
    DbManager db;
    return db.GetSTIGCheck(stigCheckId);
}

/**
 * @brief CKLCheck::GetSeverity
 * @return The @a Severity of this check.
 *
 * When the @a Severity is overridden, the overridden @a Severity is
 * returned. Otherwise, the @a STIGCheck's default @a Severity is
 * returned.
 */
Severity CKLCheck::GetSeverity() const
{
    if (severityOverride == Severity::none)
        return GetSTIGCheck().severity;
    return severityOverride;
}

/**
 * @brief CKLCheck::operator =
 * @param right
 * @return This @a CKLCheck, copied from the assignee.
 *
 * Deep copy assignment operator.
 */
CKLCheck &CKLCheck::operator=(const CKLCheck &right)
{
    if (this != &right)
    {
        id = right.id;
        assetId = right.assetId;
        stigCheckId = right.stigCheckId;
        status = right.status;
        findingDetails = right.findingDetails;
        comments = right.comments;
        severityOverride = right.severityOverride;
        severityJustification = right.severityJustification;
    }
    return *this;
}

/**
 * @brief GetStatus
 * @param status
 * @return A @a Status enum representing the provided string's
 * compliance.
 *
 * When parsing XML, several file types are inconsistent with how the
 * compliance status is stored. Passing the string to this function
 * will retrieve a standard @a Status enum from the string.
 */
Status GetStatus(const QString &status)
{
    if (status.startsWith(QStringLiteral("o"), Qt::CaseInsensitive))
        return Status::Open;
    if (status.startsWith(QStringLiteral("not_applicable"), Qt::CaseInsensitive) || status.startsWith(QStringLiteral("not applicable"), Qt::CaseInsensitive) || status.startsWith(QStringLiteral("na"), Qt::CaseInsensitive))
        return Status::NotApplicable;
    if (status.startsWith(QStringLiteral("notafinding"), Qt::CaseInsensitive) || status.startsWith(QStringLiteral("not a finding"), Qt::CaseInsensitive) || status.startsWith(QStringLiteral("nf"), Qt::CaseInsensitive))
        return Status::NotAFinding;
    return Status::NotReviewed;
}

/**
 * @brief GetStatus
 * @param status
 * @param xmlFormat
 * @return The XML-formatted string for the compliance status.
 *
 * Converts the @a Status enum back to a human-readable (when
 * @a xmlFormat is @c false) or XML-formatted (when @a xmlFormat is
 * @c true) string.
 */
QString GetStatus(Status status, bool xmlFormat)
{
    switch (status)
    {
    case Status::Open:
        return QStringLiteral("Open");
    case Status::NotApplicable:
        return xmlFormat ? QStringLiteral("Not_Applicable") : QStringLiteral("Not Applicable");
    case Status::NotAFinding:
        return xmlFormat ? QStringLiteral("NotAFinding") : QStringLiteral("Not a Finding");
    default:
        return xmlFormat ? QStringLiteral("Not_Reviewed") : QStringLiteral("Not Reviewed");
    }
}

/**
 * @brief GetCMRSStatus
 * @param status
 * @return The CMRS-formatted string for the compliance status.
 *
 * Converts the @a Status enum back to a CMRS-standard finding.
 */
QString GetCMRSStatus(Status status)
{
    switch (status)
    {
    case Status::Open:
        return QStringLiteral("O");
    case Status::NotApplicable:
        return QStringLiteral("NA");
    case Status::NotAFinding:
        return QStringLiteral("NF");
    default:
        return QStringLiteral("NR");
    }
}

/**
 * @brief PrintCKLCheck
 * @param cklCheck
 * @return Human-readable printout of the @a STIGCheck component.
 */
[[nodiscard]] QString PrintCKLCheck(const CKLCheck &cklCheck)
{
    return PrintSTIGCheck(cklCheck.GetSTIGCheck());
}
