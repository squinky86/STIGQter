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

#ifndef STIGCHECK_H
#define STIGCHECK_H

#include "cci.h"
#include "stig.h"

#include <QObject>
#include <QString>

enum Severity
{
    high = 3,
    medium = 2,
    low = 1,
    none = 0
};

Severity GetSeverity(const QString &severity);
QString GetSeverity(const Severity &severity, bool cat = true); //cat levels or low/mod/high

class STIGCheck : public QObject
{
    Q_OBJECT
public:
    STIGCheck(const STIGCheck& right);
    STIGCheck(QObject *parent = nullptr);
    STIGCheck& operator=(const STIGCheck &right);

    int id;
    int stigId;
    int cciId;
    STIG STIG() const;
    CCI CCI() const;
    QString vulnNum;
    QString groupTitle;
    QString ruleVersion;
    QString rule;
    Severity severity;
    double weight;
    QString title;
    QString vulnDiscussion;
    QString falsePositives;
    QString falseNegatives;
    QString fix;
    QString check;
    bool documentable;
    QString mitigations;
    QString severityOverrideGuidance;
    QString checkContentRef;
    QString potentialImpact;
    QString thirdPartyTools;
    QString mitigationControl;
    QString responsibility;
    QString iaControls;
    QString targetKey;
};

Q_DECLARE_METATYPE(STIGCheck);

QString PrintSTIGCheck(STIGCheck s);

#endif // STIGCHECK_H
