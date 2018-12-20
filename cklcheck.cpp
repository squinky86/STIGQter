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

#include "cklcheck.h"
#include "dbmanager.h"

CKLCheck::CKLCheck(const CKLCheck &right) : CKLCheck(right.parent())
{
    *this = right;
}

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

Asset CKLCheck::Asset() const
{
    DbManager db;
    return db.GetAsset(assetId);
}

STIGCheck CKLCheck::STIGCheck() const
{
    DbManager db;
    return db.GetSTIGCheck(stigCheckId);
}

Severity CKLCheck::GetSeverity() const
{
    if (severityOverride == Severity::none)
        return STIGCheck().severity;
    return severityOverride;
}

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

Status GetStatus(const QString &status)
{
    if (status.startsWith("open", Qt::CaseInsensitive))
        return Status::Open;
    if (status.startsWith("not_applicable", Qt::CaseInsensitive) || status.startsWith("not applicable", Qt::CaseInsensitive))
        return Status::NotApplicable;
    if (status.startsWith("notafinding", Qt::CaseInsensitive) || status.startsWith("not a finding", Qt::CaseInsensitive))
        return Status::NotAFinding;
    return Status::NotReviewed;
}

QString GetStatus(const Status &status)
{
    switch (status)
    {
    case Status::Open:
        return "Open";
    case Status::NotApplicable:
        return "Not Applicable";
    case Status::NotAFinding:
        return "Not a Finding";
    default:
        return "Not Reviewed";
    }
}

QString PrintCKLCheck(const CKLCheck &c)
{
    return PrintSTIGCheck(c.STIGCheck());
}
