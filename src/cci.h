/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2022 Jon Hood, http://www.hoodsecurity.com/
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

#ifndef CCI_H
#define CCI_H

#include <QObject>
#include <QString>

class CKLCheck;
class Control;
class STIGCheck;

class CCI : public QObject
{
    Q_OBJECT

public:
    CCI(const CCI &right);
    explicit CCI(QObject *parent = nullptr);
    ~CCI() override = default;
    int id;
    Control GetControl() const;
    QVector<CKLCheck> GetCKLChecks() const;
    QVector<STIGCheck> GetSTIGChecks() const;
    int controlId;
    int cci;
    QString definition;
    bool isImport;
    QString importCompliance;
    QString importDateTested;
    QString importTestedBy;
    QString importTestResults;
    QString importCompliance2;
    QString importDateTested2;
    QString importTestedBy2;
    QString importTestResults2;
    QString importControlImplementationStatus;
    QString importSecurityControlDesignation;
    QString importInherited;
    QString importApNum;
    QString importImplementationGuidance;
    QString importAssessmentProcedures;
    QString importNarrative;
    friend bool operator<(const CCI &left, const CCI &right)
    {
        return left.cci < right.cci;
    }
    CCI& operator=(const CCI &right);
    bool operator==(const CCI &right) const;
};

Q_DECLARE_METATYPE(CCI);

[[nodiscard]] QString PrintCCI(int cci);
[[nodiscard]] QString PrintCCI(const CCI &cci);

#endif // CCI_H
