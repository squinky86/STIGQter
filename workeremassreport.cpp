/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019 Jon Hood, http://www.hoodsecurity.com/
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

#include "common.h"
#include "dbmanager.h"
#include "workeremassreport.h"
#include "xlsxwriter.h"

WorkerEMASSReport::WorkerEMASSReport(QObject *parent) : QObject(parent), _fileName()
{
}

void WorkerEMASSReport::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

void WorkerEMASSReport::process()
{
    DbManager db;

    QMap<CCI, QList<CKLCheck>> failedCCIs;
    QList<CKLCheck> checks = db.GetCKLChecks();
    int numChecks = checks.count();
    emit initialize(numChecks+2, 0);

    //current date in eMASS format
    QString curDate = QDate::currentDate().toString("dd-MMM-yyyy");

    //new workbook
    lxw_workbook  *wb = workbook_new(_fileName.toStdString().c_str());
    //2 sheets - findings and controls
    lxw_worksheet *ws = workbook_add_worksheet(wb, "Test Result Import");

    //add formats
    //format - bold text, centered
    lxw_format *fmtBoldCenter = workbook_add_format(wb);
    format_set_bold(fmtBoldCenter);
    format_set_align(fmtBoldCenter, LXW_ALIGN_CENTER);

    //format - green, bold text
    lxw_format *fmtBoldGreen = workbook_add_format(wb);
    format_set_bold(fmtBoldGreen);
    format_set_font_color(fmtBoldGreen, LXW_COLOR_GREEN);

    //format - bold, white text on a gray background
    lxw_format *fmtBoldGrayBG = workbook_add_format(wb);
    format_set_bold(fmtBoldGrayBG);
    format_set_fg_color(fmtBoldGrayBG, LXW_COLOR_GRAY);
    format_set_font_color(fmtBoldGrayBG, LXW_COLOR_WHITE);

    //format - white text on a gray background
    lxw_format *fmtGrayBG = workbook_add_format(wb);
    format_set_fg_color(fmtGrayBG, LXW_COLOR_GRAY);
    format_set_font_color(fmtGrayBG, LXW_COLOR_WHITE);

    //format - white text on a gray background, text-aligned right
    lxw_format *fmtGrayBGRight = workbook_add_format(wb);
    format_set_fg_color(fmtGrayBGRight, LXW_COLOR_GRAY);
    format_set_font_color(fmtGrayBGRight, LXW_COLOR_WHITE);
    format_set_align(fmtGrayBGRight, LXW_ALIGN_RIGHT);

    //format - wrapped text
    lxw_format *fmtWrapped = workbook_add_format(wb);
    format_set_text_wrap(fmtWrapped);

    //write headers for findings

    //column sizes
    worksheet_set_column(ws, 0, 0, 12.29, nullptr);
    worksheet_set_column(ws, 1, 1, 50.57, nullptr);
    worksheet_set_column(ws, 2, 2, 10.57, nullptr);
    worksheet_set_column(ws, 3, 3, 8.71, nullptr);
    worksheet_set_column(ws, 4, 4, 23.57, nullptr);
    worksheet_set_column(ws, 5, 5, 26.29, nullptr);
    worksheet_set_column(ws, 6, 6, 33.43, nullptr);
    worksheet_set_column(ws, 7, 7, 19.29, nullptr);
    worksheet_set_column(ws, 8, 8, 15.86, nullptr);
    worksheet_set_column(ws, 9, 9, 19.29, nullptr);
    worksheet_set_column(ws, 10, 10, 39.29, nullptr);
    worksheet_set_column(ws, 11, 11, 19.29, nullptr);
    worksheet_set_column(ws, 12, 12, 15.86, nullptr);
    worksheet_set_column(ws, 13, 13, 19.29, nullptr);
    worksheet_set_column(ws, 14, 14, 39.29, nullptr);

    //zoom factor
    worksheet_set_zoom(ws, 70);

    //unclassified header
    worksheet_merge_range(ws, 0, 0, 0, 14, "UNCLASSIFIED", fmtBoldGreen);
    //export date
    worksheet_merge_range(ws, 1, 0, 1, 14, (QString("Exported on ") + curDate).toStdString().c_str(), fmtGrayBGRight);
    //information on export
    worksheet_merge_range(ws, 2, 0, 2, 13, "Test Result Import Template", fmtBoldGrayBG);
    worksheet_write_string(ws, 2, 14, (QString("Provided by STIGQter ") + VERSION).toStdString().c_str(), fmtGrayBGRight);
    //IS information
    worksheet_merge_range(ws, 3, 0, 3, 14, "(System Type: UNKNOWN, DoD Component: Public)", fmtGrayBG);
    //High-Level Headers
    worksheet_merge_range(ws, 4, 0, 4, 6, "Control / AP Information", fmtBoldCenter);
    worksheet_merge_range(ws, 4, 7, 4, 10, "Enter Test Results Here", fmtBoldCenter);
    worksheet_merge_range(ws, 4, 11, 4, 14, "Latest Test Result", fmtBoldCenter);
    //column-level headers
    worksheet_write_string(ws, 5, 0, "Control Number", fmtBoldCenter);
    worksheet_write_string(ws, 5, 1, "Control Information", fmtBoldCenter);
    worksheet_write_string(ws, 5, 2, "AP Acronym", fmtBoldCenter);
    worksheet_write_string(ws, 5, 3, "CCI", fmtBoldCenter);
    worksheet_write_string(ws, 5, 4, "CCI Definition", fmtBoldCenter);
    worksheet_write_string(ws, 5, 5, "Implementation Guidance", fmtBoldCenter);
    worksheet_write_string(ws, 5, 6, "Assessment Procedures", fmtBoldCenter);
    worksheet_write_string(ws, 5, 7, "Compliance Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 8, "Date Tested", fmtBoldCenter);
    worksheet_write_string(ws, 5, 9, "Tested By", fmtBoldCenter);
    worksheet_write_string(ws, 5, 10, "Test Results", fmtBoldCenter);
    worksheet_write_string(ws, 5, 11, "Compliance Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 12, "Date Tested", fmtBoldCenter);
    worksheet_write_string(ws, 5, 13, "Tested By", fmtBoldCenter);
    worksheet_write_string(ws, 5, 14, "Test Results", fmtBoldCenter);

    //build list of failed controls and what failed
    for (int i = 0; i < numChecks; i++)
    {
        CKLCheck cc = checks[i];
        STIGCheck sc = cc.STIGCheck();
        CCI c = sc.CCI();
        Status s = cc.status;
        emit updateStatus("Checking " + PrintSTIGCheck(sc) + "…");

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

    unsigned int onRow = 5;
    for (auto i = failedCCIs.constBegin(); i != failedCCIs.constEnd(); i++)
    {
        onRow++;
        CCI c = i.key();
        emit updateStatus("Adding " + PrintCCI(c) + "…");
        QList<CKLCheck> checks = i.value();
        std::sort(checks.begin(), checks.end());
        Control control = c.Control();
        //control
        worksheet_write_string(ws, onRow, 0, PrintControl(control).toStdString().c_str(), nullptr);
        //control information
        worksheet_write_string(ws, onRow, 1, Excelify(control.description).toStdString().c_str(), fmtWrapped);
        //AP Acronym is nonsense; ignore it
        worksheet_write_string(ws, onRow, 2, "", nullptr);
        //CCI
        QString cci = QString::number(c.cci);
        while (cci.length() < 6)
            cci = "0" + cci;
        worksheet_write_string(ws, onRow, 3, cci.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 4, Excelify(c.definition).toStdString().c_str(), fmtWrapped);
        //implementation guidance and assessment procedures not available
        worksheet_write_string(ws, onRow, 5, "", nullptr);
        worksheet_write_string(ws, onRow, 6, "", nullptr);
        //compliance status
        worksheet_write_string(ws, onRow, 7, "Non-Compliant", nullptr);
        //date tested
        worksheet_write_string(ws, onRow, 8, curDate.toStdString().c_str(), nullptr);
        //tested by
        QString username = qgetenv("USER");
        if (username.isNull() || username.isEmpty())
            username = qgetenv("USERNAME");
        if (username.isNull() || username.isEmpty())
            username = "UNKNOWN";
        worksheet_write_string(ws, onRow, 9, username.toStdString().c_str(), nullptr);

        //test results
        QString testResult = "The following checks are open:";
        foreach (CKLCheck cc, checks)
        {
            testResult.append("\n" + PrintAsset(cc.Asset()) + ": " + PrintCKLCheck(cc) + " - " + GetSeverity(cc.GetSeverity()));
            if (!cc.findingDetails.isEmpty())
                testResult.append(" - " + cc.findingDetails);
        }
        worksheet_write_string(ws, onRow, 10, Excelify(testResult).toStdString().c_str(), fmtWrapped);

        //ignore previous test results
        worksheet_write_string(ws, onRow, 11, "", nullptr);
        worksheet_write_string(ws, onRow, 12, "", nullptr);
        worksheet_write_string(ws, onRow, 13, "", nullptr);
        worksheet_write_string(ws, onRow, 14, "", nullptr);

        emit progress(-1);
    }

    emit updateStatus("Writing workbook…");

    //close and write the workbook
    workbook_close(wb);

    emit updateStatus("Done!");
    emit finished();
}
