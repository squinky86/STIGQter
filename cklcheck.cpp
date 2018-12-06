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

CKLCheck::CKLCheck(const CKLCheck &right) : CKLCheck(right.parent())
{
    *this = right;
}

CKLCheck::CKLCheck(QObject *parent) : QObject(parent)
{
}

CKLCheck &CKLCheck::operator=(const CKLCheck &right)
{
    if (this != &right)
    {
        AssetId = right.AssetId;
        STIGCheckId = right.STIGCheckId;
        status = right.status;
        findingDetails = right.findingDetails;
        comments = right.comments;
        severityOverride = right.severityOverride;
        severityJustification = right.severityJustification;
    }
    return *this;
}
