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

#include <QDate>

#include "common.h"
#include "dbmanager.h"
#include "workeremassreport.h"
#include "xlsxwriter.h"

/**
 * @class WorkerEMASSReport
 * @brief Export an eMASS-compatible Test Result Import (TR) report.
 *
 * eMASS uses a TR import spreadsheet to quickly process data. The
 * format for this spreadsheet is duplicated by this report so that
 * the results generated for the system can be directly imported into
 * eMASS.
 */

/**
 * @brief WorkerEMASSReport::WorkerEMASSReport
 * @param parent
 *
 * Default constructor.
 */
WorkerEMASSReport::WorkerEMASSReport(QObject *parent) : QObject(parent), _fileName()
{
}

/**
 * @brief WorkerEMASSReport::SetReportName
 * @param fileName
 *
 * Set the location of the file to write to (should end in .xlsx).
 */
void WorkerEMASSReport::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

/**
 * @brief WorkerEMASSReport::process
 *
 * Write the report to the selected file location. The spreadsheet is
 * written in a format compatible with eMASS.
 */
void WorkerEMASSReport::process()
{
    DbManager db;

    QMap<CCI, QList<CKLCheck>> failedCCIs;
    QMap<CCI, QList<CKLCheck>> passedCCIs;
    QList<CKLCheck> checks = db.GetCKLChecks();
    int numChecks = checks.count();
    emit initialize(numChecks+2, 0);

    //current date in eMASS format
    QString curDate = QDate::currentDate().toString(QStringLiteral("dd-MMM-yyyy"));
    //current date in Excel format
    QDate tempDate(1899, 12, 31);
    qint64 excelCurDate = QDate::currentDate().toJulianDay() - tempDate.toJulianDay() + 1;

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

    //format - date/time
    lxw_format *fmtDate = workbook_add_format(wb);
    format_set_num_format(fmtDate, "[$-en-US]dd-mmm-yyyy;@");

    //write headers for findings

    //column sizes
    worksheet_set_column(ws, 0, 0, 12.29, nullptr);
    worksheet_set_column(ws, 1, 1, 50.57, nullptr);
    worksheet_set_column(ws, 2, 2, 26.22, nullptr);
    worksheet_set_column(ws, 3, 3, 26.22, nullptr);
    worksheet_set_column(ws, 4, 4, 10.57, nullptr);
    worksheet_set_column(ws, 5, 5, 8.71, nullptr);
    worksheet_set_column(ws, 6, 6, 23.57, nullptr);
    worksheet_set_column(ws, 7, 7, 26.29, nullptr);
    worksheet_set_column(ws, 8, 8, 33.43, nullptr);
    worksheet_set_column(ws, 9, 9, 19.89, nullptr);
    worksheet_set_column(ws, 10, 10, 19.29, nullptr);
    worksheet_set_column(ws, 11, 11, 15.86, nullptr);
    worksheet_set_column(ws, 12, 12, 19.29, nullptr);
    worksheet_set_column(ws, 13, 13, 39.29, nullptr);
    worksheet_set_column(ws, 14, 14, 19.29, nullptr);
    worksheet_set_column(ws, 15, 15, 15.86, nullptr);
    worksheet_set_column(ws, 16, 16, 19.29, nullptr);
    worksheet_set_column(ws, 17, 17, 39.29, nullptr);

    //zoom factor
    worksheet_set_zoom(ws, 70);

    //unclassified header
    worksheet_merge_range(ws, 0, 0, 0, 17, "UNCLASSIFIED", fmtBoldGreen);
    //export date
    worksheet_merge_range(ws, 1, 0, 1, 17, (QStringLiteral("Exported on ") + curDate).toStdString().c_str(), fmtGrayBGRight);
    //information on export
    worksheet_merge_range(ws, 2, 0, 2, 16, "Test Result Import Template", fmtBoldGrayBG);
    worksheet_write_string(ws, 2, 17, (QStringLiteral("Provided by STIGQter ") + VERSION).toStdString().c_str(), fmtGrayBGRight);
    //IS information
    worksheet_merge_range(ws, 3, 0, 3, 17, "(System Type: UNKNOWN, DoD Component: Public)", fmtGrayBG);
    //High-Level Headers
    worksheet_merge_range(ws, 4, 0, 4, 9, "Control / AP Information", fmtBoldCenter);
    worksheet_merge_range(ws, 4, 10, 4, 13, "Enter Test Results Here", fmtBoldCenter);
    worksheet_merge_range(ws, 4, 14, 4, 17, "Latest Test Result", fmtBoldCenter);
    //column-level headers
    worksheet_write_string(ws, 5, 0, "Control Acronym", fmtBoldCenter);
    worksheet_write_string(ws, 5, 1, "Control Information", fmtBoldCenter);
    worksheet_write_string(ws, 5, 2, "Control Implementation Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 3, "Security Control Designation", fmtBoldCenter);
    worksheet_write_string(ws, 5, 4, "AP Acronym", fmtBoldCenter);
    worksheet_write_string(ws, 5, 5, "CCI", fmtBoldCenter);
    worksheet_write_string(ws, 5, 6, "CCI Definition", fmtBoldCenter);
    worksheet_write_string(ws, 5, 7, "Implementation Guidance", fmtBoldCenter);
    worksheet_write_string(ws, 5, 8, "Assessment Procedures", fmtBoldCenter);
    worksheet_write_string(ws, 5, 9, "Inherited", fmtBoldCenter);
    worksheet_write_string(ws, 5, 10, "Compliance Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 11, "Date Tested", fmtBoldCenter);
    worksheet_write_string(ws, 5, 12, "Tested By", fmtBoldCenter);
    worksheet_write_string(ws, 5, 13, "Test Results", fmtBoldCenter);
    worksheet_write_string(ws, 5, 14, "Compliance Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 15, "Date Tested", fmtBoldCenter);
    worksheet_write_string(ws, 5, 16, "Tested By", fmtBoldCenter);
    worksheet_write_string(ws, 5, 17, "Test Results", fmtBoldCenter);

    //build list of failed controls and what failed
    for (int i = 0; i < numChecks; i++)
    {
        CKLCheck cc = checks[i];
        STIGCheck sc = cc.GetSTIGCheck();
        QList<CCI> ccis = sc.GetCCIs();
        Status s = cc.status;
        emit updateStatus("Checking " + PrintSTIGCheck(sc) + "…");

        //if the check is a finding, add it to the CCI sheet
        foreach (CCI c, ccis)
        {
            if (s == Status::Open)
            {
                if (passedCCIs.contains(c))
                    passedCCIs.remove(c);
                if (failedCCIs.contains(c))
                    failedCCIs[c].append(cc);
                else
                    failedCCIs.insert(c, {cc});
            }
            else if (s == Status::NotAFinding && !failedCCIs.contains(c))
            {
                if (passedCCIs.contains(c))
                    passedCCIs[c].append(cc);
                else
                    passedCCIs.insert(c, {cc});
            }
        }
        emit progress(-1);
    }

    emit initialize(numChecks+failedCCIs.count()+1, numChecks);

    unsigned int onRow = 5;

    //print out all failed CCIs
    QString username = qgetenv("USER");
    if (username.isNull() || username.isEmpty())
        username = qgetenv("USERNAME");
    if (username.isNull() || username.isEmpty())
        username = QStringLiteral("UNKNOWN");

    bool unimportedCCI = false;

    for (auto i = failedCCIs.constBegin(); i != failedCCIs.constEnd(); i++)
    {
        onRow++;
        CCI c = i.key();
        emit updateStatus("Adding " + PrintCCI(c) + "…");
        QList<CKLCheck> checks = i.value();
        std::sort(checks.begin(), checks.end());
        Control control = c.GetControl();
        //control acronym
        worksheet_write_string(ws, onRow, 0, PrintControl(control).toStdString().c_str(), nullptr);
        //control information
        worksheet_write_string(ws, onRow, 1, Excelify(control.description).toStdString().c_str(), fmtWrapped);
        //control implementation status
        worksheet_write_string(ws, onRow, 2, c.isImport ? c.importControlImplementationStatus.toStdString().c_str() : "", nullptr);
        //security control designation
        worksheet_write_string(ws, onRow, 3, c.isImport ? c.importSecurityControlDesignation.toStdString().c_str() : "", nullptr);
        //AP Acronym
        worksheet_write_string(ws, onRow, 4, c.isImport ? c.importApNum.toStdString().c_str() : "", nullptr);
        //CCI
        QString cci = QString::number(c.cci);
        while (cci.length() < 6)
            cci = "0" + cci;
        worksheet_write_string(ws, onRow, 5, cci.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 6, Excelify(c.definition).toStdString().c_str(), fmtWrapped);
        //implementation guidance and assessment procedures not available
        worksheet_write_string(ws, onRow, 7, c.isImport ? c.importImplementationGuidance.toStdString().c_str() : "", fmtWrapped);
        worksheet_write_string(ws, onRow, 8, c.isImport ? c.importAssessmentProcedures.toStdString().c_str() : "", fmtWrapped);
        //inherited
        worksheet_write_string(ws, onRow, 9, c.isImport ? c.importInherited.toStdString().c_str() : "", fmtWrapped);
        //compliance status
        worksheet_write_string(ws, onRow, 10, "Non-Compliant", nullptr);
        //date tested
        worksheet_write_number(ws, onRow, 11, excelCurDate, fmtDate);
        //tested by
        worksheet_write_string(ws, onRow, 12, username.toStdString().c_str(), nullptr);

        //test results
        QString testResult = c.importTestResults2;
        if (!testResult.isEmpty())
            testResult += "\n";
        testResult += QStringLiteral("The following checks are open:");
        foreach (CKLCheck cc, checks)
        {
            testResult.append("\n" + PrintAsset(cc.GetAsset()) + ": " + PrintCKLCheck(cc) + " - " + GetSeverity(cc.GetSeverity()));
            if (!cc.findingDetails.isEmpty())
                testResult.append(" - " + cc.findingDetails);
        }
        worksheet_write_string(ws, onRow, 13, Excelify(testResult).toStdString().c_str(), fmtWrapped);

        if (!c.isImport)
            unimportedCCI = true;

        //ignore previous test results
        worksheet_write_string(ws, onRow, 14, c.isImport ? c.importCompliance.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 15, c.isImport ? c.importDateTested.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 16, c.isImport ? c.importTestedBy.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 17, c.isImport ? c.importTestResults.toStdString().c_str() : "", fmtWrapped);

        emit progress(-1);
    }

    //print out all passed CCIs
    for (auto i = passedCCIs.constBegin(); i != passedCCIs.constEnd(); i++)
    {
        onRow++;
        CCI c = i.key();
        emit updateStatus("Adding " + PrintCCI(c) + "…");
        QList<CKLCheck> checks = i.value();
        std::sort(checks.begin(), checks.end());
        Control control = c.GetControl();
        //control
        worksheet_write_string(ws, onRow, 0, PrintControl(control).toStdString().c_str(), nullptr);
        //control information
        worksheet_write_string(ws, onRow, 1, Excelify(control.description).toStdString().c_str(), fmtWrapped);
        //control implementation status
        worksheet_write_string(ws, onRow, 2, c.isImport ? c.importControlImplementationStatus.toStdString().c_str() : "", nullptr);
        //security control designation
        worksheet_write_string(ws, onRow, 3, c.isImport ? c.importSecurityControlDesignation.toStdString().c_str() : "", nullptr);
        //AP Acronym is nonsense; ignore it
        worksheet_write_string(ws, onRow, 4, c.isImport ? c.importApNum.toStdString().c_str() : "", nullptr);
        //CCI
        QString cci = QString::number(c.cci);
        while (cci.length() < 6)
            cci = "0" + cci;
        worksheet_write_string(ws, onRow, 5, cci.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 6, Excelify(c.definition).toStdString().c_str(), fmtWrapped);
        //implementation guidance and assessment procedures not available
        worksheet_write_string(ws, onRow, 7, c.isImport ? c.importImplementationGuidance.toStdString().c_str() : "", fmtWrapped);
        worksheet_write_string(ws, onRow, 8, c.isImport ? c.importAssessmentProcedures.toStdString().c_str() : "", fmtWrapped);
        //inherited
        worksheet_write_string(ws, onRow, 9, c.isImport ? c.importInherited.toStdString().c_str() : "", fmtWrapped);
        //compliance status
        worksheet_write_string(ws, onRow, 10, "Compliant", nullptr);
        //date tested
        worksheet_write_number(ws, onRow, 11, excelCurDate, fmtDate);
        //tested by
        worksheet_write_string(ws, onRow, 12, username.toStdString().c_str(), nullptr);

        //test results
        QString testResult = c.importTestResults2;
        if (!testResult.isEmpty())
            testResult += "\n";
        testResult += QStringLiteral("The following checks were compliant:");
        foreach (CKLCheck cc, checks)
        {
            testResult.append("\n" + PrintAsset(cc.GetAsset()) + ": " + PrintCKLCheck(cc));
        }
        worksheet_write_string(ws, onRow, 13, Excelify(testResult).toStdString().c_str(), fmtWrapped);

        if (!c.isImport)
            unimportedCCI = true;

        //previous test results
        worksheet_write_string(ws, onRow, 14, c.isImport ? c.importCompliance.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 15, c.isImport ? c.importDateTested.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 16, c.isImport ? c.importTestedBy.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 17, c.isImport ? c.importTestResults.toStdString().c_str() : "", fmtWrapped);

        emit progress(-1);
    }

    //print out all old test results
    foreach (const CCI &c, db.GetCCIs())
    {
        if (!c.isImport || failedCCIs.contains(c) || passedCCIs.contains(c))
            continue;

        onRow++;
        emit updateStatus("Adding " + PrintCCI(c) + "…");
        Control control = c.GetControl();
        //control
        worksheet_write_string(ws, onRow, 0, PrintControl(control).toStdString().c_str(), nullptr);
        //control information
        worksheet_write_string(ws, onRow, 1, Excelify(control.description).toStdString().c_str(), fmtWrapped);
        //control implementation status
        worksheet_write_string(ws, onRow, 2, c.isImport ? c.importControlImplementationStatus.toStdString().c_str() : "", nullptr);
        //security control designation
        worksheet_write_string(ws, onRow, 3, c.isImport ? c.importSecurityControlDesignation.toStdString().c_str() : "", nullptr);
        //AP Acronym is nonsense; ignore it
        worksheet_write_string(ws, onRow, 4, c.isImport ? c.importApNum.toStdString().c_str() : "", nullptr);
        //CCI
        QString cci = QString::number(c.cci);
        while (cci.length() < 6)
            cci = "0" + cci;
        worksheet_write_string(ws, onRow, 5, cci.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 6, Excelify(c.definition).toStdString().c_str(), fmtWrapped);
        //implementation guidance and assessment procedures not available
        worksheet_write_string(ws, onRow, 7, c.isImport ? c.importImplementationGuidance.toStdString().c_str() : "", fmtWrapped);
        worksheet_write_string(ws, onRow, 8, c.isImport ? c.importAssessmentProcedures.toStdString().c_str() : "", fmtWrapped);
        //inherited
        worksheet_write_string(ws, onRow, 9, c.isImport ? c.importInherited.toStdString().c_str() : "", fmtWrapped);
        //compliance status
        worksheet_write_string(ws, onRow, 10, c.importCompliance2.toStdString().c_str(), nullptr);
        //date tested
        bool ok = false;
        int tmpInt = c.importDateTested2.toInt(&ok);
        if (ok)
            worksheet_write_number(ws, onRow, 11, tmpInt, fmtDate);
        else
            worksheet_write_number(ws, onRow, 11, excelCurDate, fmtDate);
        //tested by
        worksheet_write_string(ws, onRow, 12, c.importTestedBy2.toStdString().c_str(), nullptr);

        //test results
        worksheet_write_string(ws, onRow, 13, c.importTestResults2.toStdString().c_str(), fmtWrapped);

        //previous test results
        worksheet_write_string(ws, onRow, 14, c.isImport ? c.importCompliance.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 15, c.isImport ? c.importDateTested.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 16, c.isImport ? c.importTestedBy.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 17, c.isImport ? c.importTestResults.toStdString().c_str() : "", fmtWrapped);

        emit progress(-1);
    }

    if (unimportedCCI && db.IsEmassImport())
        Warning(QStringLiteral("New CCI Detected"), QStringLiteral("One or more CCIs were detected that were not part of the eMASS TR Import. Please check your exported spreadsheet for test results that do not have data in the \"Latest Test Results\" columns."));

    emit updateStatus(QStringLiteral("Writing workbook…"));

    //close and write the workbook
    workbook_close(wb);

    emit updateStatus(QStringLiteral("Done!"));
    emit finished();
}
