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

#ifndef CKLCHECK_H
#define CKLCHECK_H

#include <QObject>
#include <QString>

#include "asset.h"
#include "stigcheck.h"

enum Status
{
    NotReviewed,
    Open,
    NotAFinding,
    NotApplicable
};

Status GetStatus(const QString &status);
QString GetStatus(const Status &status, bool xmlFormat = false);

class CKLCheck : public QObject
{
    Q_OBJECT

public:
    CKLCheck(const CKLCheck &right);
    CKLCheck(QObject *parent = nullptr);
    int id;
    int assetId;
    int stigCheckId;
    Asset Asset() const;
    STIGCheck STIGCheck() const;
    Severity GetSeverity() const;
    Status status;
    QString findingDetails;
    QString comments;
    Severity severityOverride;
    QString severityJustification;
    friend bool operator<(const CKLCheck &left, const CKLCheck &right)
    {
        Severity l = left.GetSeverity();
        Severity r = right.GetSeverity();
        if (l == r)
            return (left.STIGCheck().rule.compare(right.STIGCheck().rule) < 0);
        return r < l;
    }
    CKLCheck& operator=(const CKLCheck &right);
};

Q_DECLARE_METATYPE(CKLCheck);

QString PrintCKLCheck(const CKLCheck &cklCheck);

#endif // CKLCHECK_H
