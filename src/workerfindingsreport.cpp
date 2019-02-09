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

#include <algorithm>

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

    QMap<CCI, QList<CKLCheck>> failedCCIs;
    QList<CKLCheck> checks = db.GetCKLChecks();
    int numChecks = checks.count();
    emit initialize(numChecks+3, 0);

    //new workbook
    lxw_workbook  *wb = workbook_new(_fileName.toStdString().c_str());
    //2 sheets - findings and controls
    lxw_worksheet *wsFindings = workbook_add_worksheet(wb, "Findings");
    lxw_worksheet *wsCCIs = workbook_add_worksheet(wb, "CCIs");
    //add formats
    lxw_format *fmtBold = workbook_add_format(wb);
    lxw_format *fmtCci = workbook_add_format(wb);
    lxw_format *fmtWrapped = workbook_add_format(wb);
    format_set_text_wrap(fmtWrapped);
    format_set_num_format(fmtCci, "CCI-000000");
    format_set_bold(fmtBold);

    //write headers for findings
    worksheet_write_string(wsFindings, 0, 0, "ID", fmtBold);
    worksheet_write_string(wsFindings, 0, 1, "Host", fmtBold);
    worksheet_write_string(wsFindings, 0, 2, "Status", fmtBold);
    worksheet_write_string(wsFindings, 0, 3, "Severity", fmtBold);
    worksheet_set_column(wsFindings, 4, 4, 10, nullptr);
    worksheet_write_string(wsFindings, 0, 4, "CCI", fmtBold);
    worksheet_set_column(wsFindings, 5, 5, 18, nullptr);
    worksheet_write_string(wsFindings, 0, 5, "Rule", fmtBold);
    worksheet_write_string(wsFindings, 0, 6, "Vuln", fmtBold);
    worksheet_write_string(wsFindings, 0, 7, "Discussion", fmtBold);
    worksheet_write_string(wsFindings, 0, 8, "Details", fmtBold);
    worksheet_write_string(wsFindings, 0, 9, "Comments", fmtBold);

    //write headers for CCI findings
    worksheet_write_string(wsCCIs, 0, 0, "Control", fmtBold);
    worksheet_set_column(wsCCIs, 1, 1, 10, nullptr);
    worksheet_write_string(wsCCIs, 0, 1, "CCI", fmtBold);
    worksheet_write_string(wsCCIs, 0, 2, "Severity", fmtBold);
    worksheet_write_string(wsCCIs, 0, 3, "Checks", fmtBold);
    worksheet_set_column(wsCCIs, 3, 3, 18, fmtBold);

    //write each failed check
    for (int i = 0; i < numChecks; i++)
    {
        auto onRow = static_cast<unsigned int>(i+1);
        CKLCheck cc = checks[i];
        STIGCheck sc = cc.STIGCheck();
        CCI c = sc.CCI();
        Asset a = cc.Asset();
        Status s = cc.status;
        emit updateStatus("Adding " + PrintAsset(a) + ", " + PrintSTIGCheck(sc) + "…");
        //internal id
        worksheet_write_number(wsFindings, onRow, 0, cc.id, nullptr);
        //host
        worksheet_write_string(wsFindings, onRow, 1, a.hostName.toStdString().c_str(), nullptr);
        //status
        worksheet_write_string(wsFindings, onRow, 2, GetStatus(s).toStdString().c_str(), nullptr);
        //severity
        worksheet_write_string(wsFindings, onRow, 3, GetSeverity(cc.GetSeverity()).toStdString().c_str(), nullptr);
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
            if (failedCCIs.contains(c))
                failedCCIs[c].append(cc);
            else
                failedCCIs.insert(c, {cc});
        }
        emit progress(-1);
    }

    emit initialize(numChecks+failedCCIs.count()+1, numChecks);

    unsigned int onRow = 0;
    for (auto i = failedCCIs.constBegin(); i != failedCCIs.constEnd(); i++)
    {
        onRow++;
        CCI c = i.key();
        emit updateStatus("Adding " + PrintCCI(c) + "…");
        QList<CKLCheck> checks = i.value();
        std::sort(checks.begin(), checks.end());
        Control control = c.Control();
        //control
        worksheet_write_string(wsCCIs, onRow, 0, PrintControl(control).toStdString().c_str(), nullptr);
        //cci
        worksheet_write_number(wsCCIs, onRow, 1, c.cci, fmtCci);
        //severity
        worksheet_write_string(wsCCIs, onRow, 2, GetSeverity(checks.first().GetSeverity()).toStdString().c_str(), nullptr);
        //Checks
        QString assets = QString();
        foreach (CKLCheck cc, checks)
        {
            if (!assets.isEmpty())
                assets.append("\n");
            assets.append(PrintCKLCheck(cc));
        }
        worksheet_write_string(wsCCIs, onRow, 3, assets.toStdString().c_str(), fmtWrapped);
        emit progress(-1);
    }

    emit updateStatus(QStringLiteral("Writing workbook…"));

    //close and write the workbook
    workbook_close(wb);

    emit updateStatus(QStringLiteral("Done!"));
    emit finished();
}
