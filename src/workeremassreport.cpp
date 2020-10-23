/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019-2020 Jon Hood, http://www.hoodsecurity.com/
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
 * @brief WorkerEMASSReport::DateChooser
 * @param isImport
 * @param curDate
 * @param importDate
 * @param useCurDate
 *
 * Return the correct date format
 */
qint64 WorkerEMASSReport::DateChooser(bool isImport, qint64 curDate, const QString &importDate, bool useCurDate = false)
{
    if (useCurDate)
        return curDate;

    if (isImport)
    {
        qint64 tmpRet = importDate.toInt();
        if (tmpRet > 0)
            return tmpRet;
    }

    return curDate;
}

/**
 * @brief WorkerEMASSReport::WorkerEMASSReport
 * @param parent
 *
 * Default constructor.
 */
WorkerEMASSReport::WorkerEMASSReport(QObject *parent) : Worker(parent), _fileName()
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

    QVector<CKLCheck> checks = db.GetCKLChecks();
    int numChecks = checks.count();
    Q_EMIT initialize(numChecks+2, 0);

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
    worksheet_set_column(ws, 4, 4, 60.78, nullptr);
    worksheet_set_column(ws, 5, 5, 10.57, nullptr);
    worksheet_set_column(ws, 6, 6, 8.71, nullptr);
    worksheet_set_column(ws, 7, 7, 23.57, nullptr);
    worksheet_set_column(ws, 8, 8, 26.29, nullptr);
    worksheet_set_column(ws, 9, 9, 33.43, nullptr);
    worksheet_set_column(ws, 10, 10, 19.89, nullptr);
    worksheet_set_column(ws, 11, 11, 19.29, nullptr);
    worksheet_set_column(ws, 12, 12, 15.86, nullptr);
    worksheet_set_column(ws, 13, 13, 19.29, nullptr);
    worksheet_set_column(ws, 14, 14, 39.29, nullptr);
    worksheet_set_column(ws, 15, 15, 19.29, nullptr);
    worksheet_set_column(ws, 16, 16, 15.86, nullptr);
    worksheet_set_column(ws, 17, 17, 19.29, nullptr);
    worksheet_set_column(ws, 18, 18, 39.29, nullptr);

    //zoom factor
    worksheet_set_zoom(ws, 70);

    //unclassified header
    worksheet_merge_range(ws, 0, 0, 0, 18, "UNCLASSIFIED", fmtBoldGreen);
    //export date
    worksheet_merge_range(ws, 1, 0, 1, 18, (QStringLiteral("Exported on ") + curDate).toStdString().c_str(), fmtGrayBGRight);
    //information on export
    worksheet_merge_range(ws, 2, 0, 2, 18, "Test Result Import Template", fmtBoldGrayBG);
    worksheet_write_string(ws, 2, 17, (QStringLiteral("Provided by STIGQter ") + VERSION).toStdString().c_str(), fmtGrayBGRight);
    //IS information
    worksheet_merge_range(ws, 3, 0, 3, 18, "(System Type: UNKNOWN, DoD Component: Public)", fmtGrayBG);
    //High-Level Headers
    worksheet_merge_range(ws, 4, 0, 4, 10, "Control / AP Information", fmtBoldCenter);
    worksheet_merge_range(ws, 4, 11, 4, 14, "Enter Test Results Here", fmtBoldCenter);
    worksheet_merge_range(ws, 4, 15, 4, 18, "Latest Test Result", fmtBoldCenter);
    //column-level headers
    worksheet_write_string(ws, 5, 0, "Control Acronym", fmtBoldCenter);
    worksheet_write_string(ws, 5, 1, "Control Information", fmtBoldCenter);
    worksheet_write_string(ws, 5, 2, "Control Implementation Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 3, "Security Control Designation", fmtBoldCenter);
    worksheet_write_string(ws, 5, 4, "Control Implementation Narrative", fmtBoldCenter);
    worksheet_write_string(ws, 5, 5, "AP Acronym", fmtBoldCenter);
    worksheet_write_string(ws, 5, 6, "CCI", fmtBoldCenter);
    worksheet_write_string(ws, 5, 7, "CCI Definition", fmtBoldCenter);
    worksheet_write_string(ws, 5, 8, "Implementation Guidance", fmtBoldCenter);
    worksheet_write_string(ws, 5, 9, "Assessment Procedures", fmtBoldCenter);
    worksheet_write_string(ws, 5, 10, "Inherited", fmtBoldCenter);
    worksheet_write_string(ws, 5, 11, "Compliance Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 12, "Date Tested", fmtBoldCenter);
    worksheet_write_string(ws, 5, 13, "Tested By", fmtBoldCenter);
    worksheet_write_string(ws, 5, 14, "Test Results", fmtBoldCenter);
    worksheet_write_string(ws, 5, 15, "Compliance Status", fmtBoldCenter);
    worksheet_write_string(ws, 5, 16, "Date Tested", fmtBoldCenter);
    worksheet_write_string(ws, 5, 17, "Tested By", fmtBoldCenter);
    worksheet_write_string(ws, 5, 18, "Test Results", fmtBoldCenter);

    bool dbIsImport = db.IsEmassImport();

    QVector<CCI> ccis = db.GetCCIs();

    Q_EMIT initialize(ccis.count()+1, 0);

    unsigned int onRow = 5;

    QString username(QString::fromLocal8Bit(qgetenv("USER")));
    if (username.isNull() || username.isEmpty())
        username = QString::fromLocal8Bit(qgetenv("USERNAME"));
    if (username.isNull() || username.isEmpty())
        username = QStringLiteral("UNKNOWN");

    QVector<CKLCheck> failedChecks;
    QVector<CKLCheck> passedChecks;

    Q_FOREACH (CCI cci, db.GetCCIs())
    {
        Q_EMIT progress(-1);
        Q_EMIT updateStatus("Adding " + PrintCCI(cci) + "…");
        failedChecks.clear();
        passedChecks.clear();

        //step 1: check if control is passed or failed
        Q_FOREACH (CKLCheck sc, cci.GetCKLChecks())
        {
            if (sc.status == Status::Open)
            {
                failedChecks.append(sc);
            }
            else if (sc.status == Status::NotAFinding)
            {
                passedChecks.append(sc);
            }
        }

        //step 2: print out pass/fail/unchecked status
        /*
         * There are three cases here:
         * 1) If an eMASS record was imported and the result is a
         * pass, print the result only if the control is imported.
         * 2) If an eMASS record was imported and the result is a
         * fail, print the result and throw a warning if the mapping
         * is incorrect
         * 3) If an eMASS record was not imported, print the pass or
         * fail results as they are.
         */
        bool failed = failedChecks.count() > 0;
        bool hasChecks = failed || passedChecks.count() > 0;

        if (dbIsImport && !cci.isImport)
        {
            if (failed)
            {
                //step 2 case 2
                Warning(QStringLiteral("Bad CCI Mapping"), "Failed checks map against " + PrintCCI(cci) + ", but it is not part of the baseline. Please remap checks to CM-6 or take special notice of checks that do not have previous import data.");
            }
            else
            {
                //step 2 case 1
                //passed/no checks, but CCI is not in import. Ignore.
                continue;
            }
        }
        else if (!cci.isImport && !hasChecks)
        {
            //not import and no checks
            continue;
        }

        //print out check
        onRow++;
        //sort only failed checks
        if (failed)
        {
            std::sort(failedChecks.begin(), failedChecks.end());
        }
        Control control = cci.GetControl();
        //control
        worksheet_write_string(ws, onRow, 0, PrintControl(control).toStdString().c_str(), nullptr);
        //control information
        worksheet_write_string(ws, onRow, 1, Excelify(control.description).toStdString().c_str(), fmtWrapped);
        //control implementation status
        worksheet_write_string(ws, onRow, 2, cci.isImport ? cci.importControlImplementationStatus.toStdString().c_str() : "", nullptr);
        //security control designation
        worksheet_write_string(ws, onRow, 3, cci.isImport ? cci.importSecurityControlDesignation.toStdString().c_str() : "", nullptr);
	//Control Implementation Narrative
	
        worksheet_write_string(ws, onRow, 4, cci.isImport ? cci.importNarrative.toStdString().c_str() : "", nullptr);
        //AP Acronym is nonsense; ignore it
        worksheet_write_string(ws, onRow, 5, cci.isImport ? cci.importApNum.toStdString().c_str() : "", nullptr);
        //CCI
        QString cciStr = QString::number(cci.cci);
        while (cciStr.length() < 6)
            cciStr = "0" + cciStr;
        worksheet_write_string(ws, onRow, 6, cciStr.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 7, Excelify(cci.definition).toStdString().c_str(), fmtWrapped);
        //implementation guidance and assessment procedures not available
        worksheet_write_string(ws, onRow, 8, cci.isImport ? cci.importImplementationGuidance.toStdString().c_str() : "", fmtWrapped);
        worksheet_write_string(ws, onRow, 9, cci.isImport ? cci.importAssessmentProcedures.toStdString().c_str() : "", fmtWrapped);
        //inherited
        worksheet_write_string(ws, onRow, 10, cci.isImport ? cci.importInherited.toStdString().c_str() : "", fmtWrapped);
        //compliance status
        worksheet_write_string(ws, onRow, 11, failed ? "Non-Compliant" : hasChecks ? "Compliant" : cci.importCompliance2.toStdString().c_str(), nullptr);
        //date tested
        qint64 testedDate = excelCurDate;
        bool ok = true;
        if (dbIsImport && !hasChecks)
        {
            int tmpInt = cci.importDateTested2.toInt(&ok);
            if (ok)
            {
                testedDate = tmpInt;
            }
            else
            {
                testedDate = -1;
            }
        }
        if (testedDate != -1)
        {
            worksheet_write_number(ws, onRow, 12, testedDate, fmtDate);
        }
        else
        {
            worksheet_write_string(ws, onRow, 12, "", nullptr);
        }
        //tested by
        worksheet_write_string(ws, onRow, 13, hasChecks ? username.toStdString().c_str() : cci.isImport ? cci.importTestedBy2.toStdString().c_str() : "", nullptr);

        //test results
        QString testResult = cci.importTestResults2;
        if (!testResult.isEmpty())
            testResult += QStringLiteral("\n");
        if (hasChecks)
        {
            testResult += QStringLiteral("The following checks are ");
            if (failed)
            {
                testResult += QStringLiteral("open:");
            }
            else
            {
                testResult += QStringLiteral("compliant:");
            }
            Q_FOREACH (CKLCheck cc, failed ? failedChecks : passedChecks)
            {
                testResult.append("\n" + PrintAsset(cc.GetAsset()) + ": " + PrintCKLCheck(cc));
                //if failed check, print out severity and finding details (if available)
                if (failed)
                {
                    testResult.append(" - " + GetSeverity(cc.GetSeverity()));
                    if (!cc.findingDetails.isEmpty())
                    {
                        testResult.append(" - " + cc.findingDetails);
                    }
                }
            }
        }
        worksheet_write_string(ws, onRow, 14, Excelify(testResult).toStdString().c_str(), fmtWrapped);

        //previous test results
        worksheet_write_string(ws, onRow, 15, cci.isImport ? cci.importCompliance.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 16, cci.isImport ? cci.importDateTested.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 17, cci.isImport ? cci.importTestedBy.toStdString().c_str() : "", nullptr);
        worksheet_write_string(ws, onRow, 18, cci.isImport ? cci.importTestResults.toStdString().c_str() : "", fmtWrapped);
    }

    Q_EMIT updateStatus(QStringLiteral("Writing workbook…"));

    //filter on column 1
    worksheet_autofilter(ws, 5, 0, onRow, 17);

    //close and write the workbook
    workbook_close(wb);

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
