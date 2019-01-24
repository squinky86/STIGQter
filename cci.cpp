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

#include "cci.h"
#include "dbmanager.h"

#include <QDebug>

/*!
 * \class CCI
 * \brief A Control Correlation Identifier (CCI) corresponds to a
 * particular RMF checklist item. The RMF hierarchy consists of
 * Family → Control → CCI.
 *
 * A CCI is also referred to as an "Assessment Procedure" or AP. The
 * current list of AP numbers is not available from a standard
 * repository.
 *
 * More information about CCIs is available from
 * \l {https://iase.disa.mil/stigs/cci/Pages/index.aspx} {DISA's IASE
 * website}.
 */

/*!
 * \brief CCI::CCI
 * \param parent
 *
 * Default constructor.
 */
CCI::CCI(QObject *parent) : QObject(parent),
    id(-1),
    controlId(-1),
    cci(0),
    definition(),
    isImport(false),
    importCompliance(),
    importDateTested(),
    importTestedBy(),
    importTestResults()
{
}

/*!
 * \brief CCI::Control
 * \return the RMF control associated with this CCI
 *
 * Control() calls the database to obtain the control which maps to
 * this CCI.
 */
Control CCI::Control()
{
    DbManager db;
    return db.GetControl(controlId);
}

/*!
 * \overload CCI::CCI()
 * \brief CCI::CCI
 * \param right
 *
 * Copy constructor.
 */
CCI::CCI(const CCI &right) : CCI(right.parent())
{
    *this = right;
}

/*!
 * \brief CCI::operator=
 * \param right
 * \return this CCI, copied from the assignee
 *
 * Deep copy assignment operator.
 */
CCI& CCI::operator=(const CCI &right)
{
    if (this != &right)
    {
        id = right.id;
        controlId = right.controlId;
        cci = right.cci;
        definition = right.definition;
        isImport = right.isImport;
        importCompliance = right.importCompliance;
        importDateTested = right.importDateTested;
        importTestedBy = right.importTestedBy;
        importTestResults = right.importTestResults;
    }
    return *this;
}

/*!
 * \brief CCI::operator==
 * \param right
 * \return \c true when the actual CCI numbers are the same.
 * Otherwise, \c false.
 *
 * Only the CCI number is compared, in case there is a shallow copy
 * or database inconsistency. The database IDs and compliance state
 * are irrelevant to determining if the CCI is actually the same.
 */
bool CCI::operator==(const CCI &right)
{
    if ((id <= 0) || (right.id <= 0))
    {
        return cci == right.cci;
    }
    return id == right.id;
}

/*!
 * \brief PrintCCI
 * \param cci
 * \return human-readable CCI description
 */
QString PrintCCI(int cci)
{
    return "CCI-" + QString::number(cci).rightJustified(6, '0');
}

/*!
 * \overload PrintCCI(cci)
 * \brief PrintCCI
 * \param cci
 * \return human-readable CCI description
 */
QString PrintCCI(CCI cci)
{
    return PrintCCI(cci.cci);
}
