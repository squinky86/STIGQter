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

class CKLCheck : public QObject
{
    Q_OBJECT
protected:
    int AssetId;
    int STIGCheckId;
public:
    CKLCheck(const CKLCheck &right);
    CKLCheck(QObject *parent = nullptr);
    int id;
    Asset Asset();
    STIGCheck STIGCheck(); //TODO
    Status status;
    QString findingDetails;
    QString comments;
    Severity severityOverride;
    QString severityJustification;
    CKLCheck& operator=(const CKLCheck &right);
};

Q_DECLARE_METATYPE(CKLCheck);

#endif // CKLCHECK_H
