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

#include "dbmanager.h"
#include "cklcheck.h"
#include "common.h"
#include "workerfindingsreport.h"
#include "xlsxwriter.h"

WorkerFindingsReport::WorkerFindingsReport(QObject *parent) : QObject(parent), _fileName()
{
}

void WorkerFindingsReport::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

void WorkerFindingsReport::process()
{
    DbManager db;

    QList<CCI> failedCCIs;
    QList<CKLCheck> checks = db.GetCKLChecks();
    emit initialize(checks.count()+3, 0);

    //new workbook
    lxw_workbook  *wb = workbook_new(_fileName.toStdString().c_str());
    //2 sheets - findings and controls
    lxw_worksheet *wsFindings = workbook_add_worksheet(wb, "Findings");
    lxw_worksheet *wsCCCIs = workbook_add_worksheet(wb, "CCIs");
    //add formats
    lxw_format *fmtBold = workbook_add_format(wb);
    lxw_format *fmtCci = workbook_add_format(wb);
    format_set_num_format(fmtCci, "CCI-000000");
    format_set_bold(fmtBold);

    //write headers
    worksheet_write_string(wsFindings, 0, 0, "ID", fmtBold);
    worksheet_write_string(wsFindings, 0, 1, "Host", fmtBold);
    worksheet_write_string(wsFindings, 0, 2, "Status", fmtBold);
    worksheet_write_string(wsFindings, 0, 3, "Severity", fmtBold);
    worksheet_write_string(wsFindings, 0, 4, "CCI", fmtBold);
    worksheet_write_string(wsFindings, 0, 5, "Rule", fmtBold);
    worksheet_write_string(wsFindings, 0, 6, "Vuln", fmtBold);
    worksheet_write_string(wsFindings, 0, 7, "Discussion", fmtBold);
    worksheet_write_string(wsFindings, 0, 8, "Details", fmtBold);
    worksheet_write_string(wsFindings, 0, 9, "Comments", fmtBold);
    //todo
    worksheet_write_string(wsCCCIs, 0, 0, "Col1", fmtBold);

    //write each failed check
    for (int i = 0; i < checks.count(); i++)
    {
        unsigned int onRow = static_cast<unsigned int>(i+1);
        CKLCheck cc = checks[i];
        STIGCheck sc = cc.STIGCheck();
        CCI c = sc.CCI();
        Asset a = cc.Asset();
        Status s = cc.status;
        emit updateStatus("Adding " + PrintAsset(a) + ", " + PrintSTIGCheck(sc));
        //internal id
        worksheet_write_number(wsFindings, onRow, 0, cc.id, nullptr);
        //host
        worksheet_write_string(wsFindings, onRow, 1, a.hostName.toStdString().c_str(), nullptr);
        //status
        worksheet_write_string(wsFindings, onRow, 2, GetStatus(s).toStdString().c_str(), nullptr);
        //severity
        worksheet_write_string(wsFindings, onRow, 3, (cc.severityOverride != Severity::none) ? GetSeverity(cc.severityOverride).toStdString().c_str() : GetSeverity(sc.severity).toStdString().c_str(), nullptr);
        //cci
        worksheet_write_number(wsFindings, onRow, 4, c.cci, fmtCci);
        //rule
        worksheet_write_string(wsFindings, onRow, 5, sc.rule.toStdString().c_str(), nullptr);
        //vuln
        worksheet_write_string(wsFindings, onRow, 6, sc.vulnNum.toStdString().c_str(), nullptr);
        //discussion
        worksheet_write_string(wsFindings, onRow, 7, Excelify(sc.vulnDiscussion).toStdString().c_str(), nullptr);
        //details
        worksheet_write_string(wsFindings, onRow, 8, Excelify(cc.findingDetails).toStdString().c_str(), nullptr);
        //comments
        worksheet_write_string(wsFindings, onRow, 9, Excelify(cc.comments).toStdString().c_str(), nullptr);

        //if the check is a finding, add it to the CCI sheet
        if (s == Status::Open)
        {
            if (!failedCCIs.contains(c))
            {
                failedCCIs.append(c);
            }
        }
        emit progress(-1);
    }

    //close and write the workbook
    workbook_close(wb);

    emit updateStatus("Done!");
    emit finished();
}
