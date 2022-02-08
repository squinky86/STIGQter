/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2021–2022 Jon Hood, http://www.hoodsecurity.com/
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
#include "control.h"
#include "dbmanager.h"
#include "stigcheck.h"
#include "workerpoamreport.h"
#include "xlsxwriter.h"

/**
 * @class WorkerPOAMReport
 * @brief Export an eMASS-compatible Plan of Actions and Milestones
 * (POA&M) report.
 */

/**
 * @brief WorkerPOAMReport::WorkerPOAMReport
 * @param parent
 *
 * Default constructor.
 */
WorkerPOAMReport::WorkerPOAMReport(QObject *parent) : Worker(parent), _fileName(), _apNums(true)
{
}

/**
 * @brief WorkerPOAMReport::SetReportName
 * @param fileName
 *
 * Set the location of the file to write to (should end in .xlsx).
 */
void WorkerPOAMReport::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

/**
 * @brief WorkerPOAMReport::SetAPNums
 * @param apNums
 *
 * Set whether to generate the report at the AP level rather than
 * the @a Control level
 */
void WorkerPOAMReport::SetAPNums(const bool apNums)
{
    _apNums = apNums;
}

/**
 * @brief WorkerPOAMReport::process
 *
 * Write the report to the selected file location. The spreadsheet is
 * written in a format compatible with eMASS.
 */
void WorkerPOAMReport::process()
{
    Worker::process();

    Q_EMIT updateStatus(QStringLiteral("Building spreadsheet header..."));
    DbManager db;

    QVector<CKLCheck> checks = db.GetCKLChecks();
    QMap<Control, QPair<Severity, QVector<STIGCheck>>> failedControls;
    QMap<CCI, QPair<Severity, QVector<STIGCheck>>> failedCCIs;
    int numChecks = checks.count();
    Q_EMIT initialize(numChecks+3, 0);

    //current date in eMASS format
    QString curDate = QDate::currentDate().toString(QStringLiteral("dd-MMM-yyyy"));
    //current date in Excel format
    QDate tempDate(1899, 12, 31);

    //new workbook
    lxw_workbook  *wb = workbook_new(_fileName.toStdString().c_str());
    //2 sheets - findings and controls
    lxw_worksheet *ws = workbook_add_worksheet(wb, "POA&M");

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
    worksheet_set_column(ws, 0, 0, 0, nullptr);
    worksheet_set_column(ws, 1, 1, 13.78, nullptr);
    worksheet_set_column(ws, 2, 2, 33.78, nullptr);
    worksheet_set_column(ws, 3, 3, 17.67, nullptr);
    worksheet_set_column(ws, 4, 4, 17.67, nullptr);
    worksheet_set_column(ws, 5, 5, 17.67, nullptr);
    worksheet_set_column(ws, 6, 6, 14.67, nullptr);
    worksheet_set_column(ws, 7, 7, 24.67, nullptr);
    worksheet_set_column(ws, 8, 8, 14.33, nullptr);
    worksheet_set_column(ws, 9, 9, 15.22, nullptr);
    worksheet_set_column(ws, 10, 10, 20.78, nullptr);
    worksheet_set_column(ws, 11, 11, 23.78, nullptr);
    worksheet_set_column(ws, 12, 12, 24.33, nullptr);
    worksheet_set_column(ws, 13, 13, 16.33, nullptr);
    worksheet_set_column(ws, 14, 14, 15.44, nullptr);
    worksheet_set_column(ws, 15, 15, 18.22, nullptr);
    worksheet_set_column(ws, 16, 16, 18.22, nullptr);
    worksheet_set_column(ws, 17, 17, 18.22, nullptr);
    worksheet_set_column(ws, 18, 18, 18.22, nullptr);
    worksheet_set_column(ws, 19, 19, 26.67, nullptr);
    worksheet_set_column(ws, 20, 20, 18.22, nullptr);
    worksheet_set_column(ws, 21, 21, 29.89, nullptr);

    //zoom factor
    worksheet_set_zoom(ws, 70);

    //Row 1:
    //Unclassified Header
    worksheet_merge_range(ws, 0, 0, 0, 21, "UNCLASSIFIED", fmtBoldGreen);

    //Row 2:
    //export date
    worksheet_merge_range(ws, 1, 0, 1, 2, "Date Exported: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 1, 3, 1, 8, curDate.toStdString().c_str(), nullptr);
    //System Type
    worksheet_merge_range(ws, 1, 9, 2, 9, "System Type: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 1, 10, 2, 11, "", nullptr);
    //OMB Project ID
    worksheet_merge_range(ws, 1, 12, 2, 12, "OMB Project ID: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 1, 13, 2, 15, "", nullptr);

    //Row 3:
    //Exported By
    QString stigqterName = QStringLiteral("STIGQter ") + VERSION;
    worksheet_merge_range(ws, 2, 0, 2, 2, "Exported By: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 2, 3, 2, 8, stigqterName.toStdString().c_str(), nullptr);

    //Row 4:
    //DoD Component
    worksheet_merge_range(ws, 3, 0, 3, 2, "DoD Component: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 3, 3, 3, 8, "", nullptr);

    //POC Name
    worksheet_write_string(ws, 3, 9, "POC Name: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 3, 10, 3, 11, "", nullptr);

    //blank
    worksheet_merge_range(ws, 3, 12, 3, 15, "", nullptr);

    //Row 5:
    //System / Project Name
    worksheet_merge_range(ws, 4, 0, 4, 2, "System / Project Name: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 4, 3, 4, 8, "", nullptr);

    //POC Phone
    worksheet_write_string(ws, 4, 9, "POC Name: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 4, 10, 4, 11, "", nullptr);

    //Security Costs
    worksheet_write_string(ws, 4, 12, "Security Costs: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 4, 13, 4, 15, "", nullptr);

    //Row 6:
    //DoD IT Registration No
    worksheet_merge_range(ws, 5, 0, 5, 2, "DoD IT Registration No: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 5, 3, 5, 8, "", nullptr);

    //POC Email
    worksheet_write_string(ws, 5, 9, "POC E-Mail: ", fmtGrayBGRight);
    worksheet_merge_range(ws, 5, 10, 5, 11, "", nullptr);

    //blank
    worksheet_merge_range(ws, 5, 12, 5, 15, "", nullptr);

    //Row 7:
    //High-Level Headers
    worksheet_write_string(ws, 6, 0, "Control Vulnerability Description", fmtBoldCenter);
    worksheet_write_string(ws, 6, 1, "POA&M Item ID", fmtBoldCenter);
    worksheet_write_string(ws, 6, 2, "Control Vulnerability Description", fmtBoldCenter);
    worksheet_write_string(ws, 6, 3, "Security Control Number (NC/NA controls only)", fmtBoldCenter);
    worksheet_write_string(ws, 6, 4, "Office/Org", fmtBoldCenter);
    worksheet_write_string(ws, 6, 5, "Security Checks", fmtBoldCenter);
    worksheet_write_string(ws, 6, 6, "Resources Required", fmtBoldCenter);
    worksheet_write_string(ws, 6, 7, "Scheduled Completion Date", fmtBoldCenter);
    worksheet_write_string(ws, 6, 8, "Milestone with Completion Dates", fmtBoldCenter);
    worksheet_write_string(ws, 6, 9, "Milestone Changes", fmtBoldCenter);
    worksheet_write_string(ws, 6, 10, "Source Identifying Vulnerability", fmtBoldCenter);
    worksheet_write_string(ws, 6, 11, "Status", fmtBoldCenter);
    worksheet_write_string(ws, 6, 12, "Comments", fmtBoldCenter);
    worksheet_write_string(ws, 6, 13, "Raw Severity", fmtBoldCenter);
    worksheet_write_string(ws, 6, 14, "Mitigations", fmtBoldCenter);
    worksheet_write_string(ws, 6, 15, "Severity", fmtBoldCenter);
    worksheet_write_string(ws, 6, 16, "Relevance of Threat", fmtBoldCenter);
    worksheet_write_string(ws, 6, 17, "Likelihood", fmtBoldCenter);
    worksheet_write_string(ws, 6, 18, "Impact", fmtBoldCenter);
    worksheet_write_string(ws, 6, 19, "Impact Description", fmtBoldCenter);
    worksheet_write_string(ws, 6, 20, "Residual Risk Level", fmtBoldCenter);
    worksheet_write_string(ws, 6, 21, "Recomendations", fmtBoldCenter);

    Q_EMIT progress(-1);

    Q_EMIT updateStatus("Finding non-compliant technical Checks...");

    //build list of non-compliant controls
    Q_FOREACH(auto a, checks)
    {
        if (a.status == Status::Open)
        {
            Severity tmpSeverity = a.GetSeverity();
            STIGCheck tmpCheck = a.GetSTIGCheck();
            auto ccis = tmpCheck.GetCCIs();
            Q_FOREACH(auto cci, ccis)
            {
                //check if CCI is imported from eMASS or not
                if (!_apNums || cci.importApNum.isEmpty())
                {
                    //The CCI was not imported - add the finding at the control level
                    auto tmpControl = cci.GetControl();

                    if (!failedControls.keys().contains(tmpControl))
                        failedControls.insert(tmpControl, {Severity::none, {}});

                    if (failedControls[tmpControl].first < tmpSeverity)
                    {
                        failedControls[tmpControl].first = tmpSeverity;
                    }

                    if (!failedControls[tmpControl].second.contains(tmpCheck))
                        failedControls[tmpControl].second.append(tmpCheck);
                }
                else
                {
                    //The CCI was imported - add the finding at the cci level
                    if (!failedCCIs.keys().contains(cci))
                    {
                        failedCCIs.insert(cci, {Severity::none, {}});
                    }

                    //set the severity of the CCI if it is now higher
                    if (failedCCIs[cci].first < tmpSeverity)
                    {
                        failedCCIs[cci].first = tmpSeverity;
                    }

                    if (!failedCCIs[cci].second.contains(tmpCheck))
                        failedCCIs[cci].second.append(tmpCheck);
                }
            }
        }
    }

    unsigned onRow = 7;

    Q_EMIT progress(-1);

    Q_EMIT updateStatus("Finding non-compliant technical CCIs...");

    //write non-compliant ccis
    QMap<CCI, QPair<Severity, QVector<STIGCheck>>>::const_iterator j = failedCCIs.constBegin();
    while (j != failedCCIs.constEnd())
    {
        CCI tmpCCI = j.key();
        Control tmpControl = tmpCCI.GetControl();
        worksheet_write_string(ws, onRow, 1, QString::number(onRow-6).toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 2, (PrintCCI(tmpCCI) + QStringLiteral(" failed STIG checks")).toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 3, tmpCCI.importApNum.toStdString().c_str(), nullptr);
        QString tmpFailed;
        Q_FOREACH(auto check, j->second)
        {
            if (!tmpFailed.isEmpty())
                tmpFailed += QStringLiteral("\r\n");
            tmpFailed += PrintSTIGCheck(check);
        }
        if (!tmpFailed.isEmpty())
            worksheet_write_string(ws, onRow, 5, tmpFailed.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 10, stigqterName.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 11, "Ongoing", nullptr);
        worksheet_write_string(ws, onRow, 12, "The referenced STIG checks were identified as OPEN.", nullptr);
        QString tmpSeverity = "";
        QString residualLevel = "";
        switch (j->first)
        {
        case (Severity::high):
            tmpSeverity = "I";
            residualLevel = "High";
            break;
        case (Severity::medium):
            tmpSeverity = "II";
            residualLevel = "Moderate";
            break;
        case (Severity::low):
            tmpSeverity = "III";
            residualLevel = "Low";
            break;
        case (Severity::none):
            residualLevel = "Very Low";
            break;
        }

        worksheet_write_string(ws, onRow, 13, tmpSeverity.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 15, residualLevel.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 17, residualLevel.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 18, residualLevel.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 20, residualLevel.toStdString().c_str(), nullptr);

        ++j;
        ++onRow;
        Q_EMIT progress(-1);
    }

    Q_EMIT progress(-1);

    Q_EMIT updateStatus("Finding non-compliant technical Controls...");

    //write non-compliant controls
    QMap<Control, QPair<Severity, QVector<STIGCheck>>>::const_iterator i = failedControls.constBegin();
    while (i != failedControls.constEnd())
    {
        Control tmpControl = i.key();
        worksheet_write_string(ws, onRow, 1, QString::number(onRow-6).toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 2, (tmpControl.title + QStringLiteral(" failed STIG checks")).toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 3, PrintControl(tmpControl).toStdString().c_str(), nullptr);
        QString tmpFailed;
        Q_FOREACH(auto check, i->second)
        {
            if (!tmpFailed.isEmpty())
                tmpFailed += QStringLiteral("\r\n");
            tmpFailed += PrintSTIGCheck(check);
        }
        if (!tmpFailed.isEmpty())
            worksheet_write_string(ws, onRow, 5, tmpFailed.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 10, stigqterName.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 11, "Ongoing", nullptr);
        worksheet_write_string(ws, onRow, 12, "The referenced STIG checks were identified as OPEN.", nullptr);
        QString tmpSeverity = "";
        QString residualLevel = "";
        switch (i->first)
        {
        case (Severity::high):
            tmpSeverity = "I";
            residualLevel = "High";
            break;
        case (Severity::medium):
            tmpSeverity = "II";
            residualLevel = "Moderate";
            break;
        case (Severity::low):
            tmpSeverity = "III";
            residualLevel = "Low";
            break;
        case (Severity::none):
            residualLevel = "Very Low";
            break;
        }

        worksheet_write_string(ws, onRow, 13, tmpSeverity.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 15, residualLevel.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 17, residualLevel.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 18, residualLevel.toStdString().c_str(), nullptr);
        worksheet_write_string(ws, onRow, 20, residualLevel.toStdString().c_str(), nullptr);

        ++i;
        ++onRow;
        Q_EMIT progress(-1);
    }

    Q_EMIT updateStatus("Finding NA controls...");

    //write not applicable controls
    if (db.IsEmassImport())
    {
        Q_FOREACH (Control c, db.GetControls())
        {
            //skip controls that are not part of the import
            if (!c.IsImport())
            {
                continue;
            }

            //skip controls that were already marked as failed
            if (failedControls.keys().contains(c))
            {
                continue;
            }

            //check for NAs at the CCI level
            if (_apNums)
            {
                Q_FOREACH (auto cci, c.GetCCIs())
                {
                    worksheet_write_string(ws, onRow, 1, QString::number(onRow-6).toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 2, (PrintCCI(cci) + QStringLiteral(" is marked NA")).toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 3, cci.importApNum.toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 10, stigqterName.toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 11, "Not Applicable", nullptr);
                    worksheet_write_string(ws, onRow, 12, "The NA justification will be stored in the Security Plan", nullptr);

                    ++onRow;
                }
            }
            else
            {
                //this is a control-level POA&M
                bool isNA = true;

                //check if all CCIs are not applicable
                Q_FOREACH (auto cci, c.GetCCIs())
                {
                    if (cci.importControlImplementationStatus.compare(QStringLiteral("Not Applicable"), Qt::CaseInsensitive) != 0)
                    {
                        isNA = false;
                        break;
                    }
                }
                if (isNA)
                {
                    worksheet_write_string(ws, onRow, 1, QString::number(onRow-6).toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 2, (c.title + QStringLiteral(" is marked NA")).toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 3, PrintControl(c).toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 10, stigqterName.toStdString().c_str(), nullptr);
                    worksheet_write_string(ws, onRow, 11, "Not Applicable", nullptr);
                    worksheet_write_string(ws, onRow, 12, "The NA justification will be stored in the Security Plan", nullptr);

                    ++onRow;
                }
            }
            Q_EMIT progress(-1);
        }
    }

    Q_EMIT updateStatus("Finding self-assessed NC controls...");

    //write non-compliant controls
    if (db.IsEmassImport())
    {
        Q_FOREACH (Control c, db.GetControls())
        {
            //skip controls that were already marked as failed
            if (failedControls.keys().contains(c))
            {
                continue;
            }

            bool isNC = false;
            //check if any CCI is NC
            Q_FOREACH (auto cci, c.GetCCIs())
            {
                if (cci.importControlImplementationStatus.compare(QStringLiteral("Non-Compliant"), Qt::CaseInsensitive) == 0)
                {
                    if (_apNums && cci.isImport)
                    {
                        worksheet_write_string(ws, onRow, 1, QString::number(onRow-6).toStdString().c_str(), nullptr);
                        worksheet_write_string(ws, onRow, 2, (PrintCCI(cci) + QStringLiteral(" is marked NA")).toStdString().c_str(), nullptr);
                        worksheet_write_string(ws, onRow, 3, cci.importApNum.toStdString().c_str(), nullptr);
                        worksheet_write_string(ws, onRow, 10, stigqterName.toStdString().c_str(), nullptr);
                        worksheet_write_string(ws, onRow, 11, "Ongoing", nullptr);
                        worksheet_write_string(ws, onRow, 12, cci.importNarrative.toStdString().c_str(), nullptr);
                        worksheet_write_string(ws, onRow, 15, "Low", nullptr);
                        worksheet_write_string(ws, onRow, 17, "Low", nullptr);
                        worksheet_write_string(ws, onRow, 18, "Low", nullptr);
                        worksheet_write_string(ws, onRow, 20, "Low", nullptr);

                        ++onRow;
                    }
                    else
                    {
                        isNC = true;
                    }
                }
            }
            if (isNC)
            {
                //should only trigger if a non-imported CCI is non-compliant
                worksheet_write_string(ws, onRow, 1, QString::number(onRow-6).toStdString().c_str(), nullptr);
                worksheet_write_string(ws, onRow, 2, (c.title + QStringLiteral(" is marked NA")).toStdString().c_str(), nullptr);
                worksheet_write_string(ws, onRow, 3, PrintControl(c).toStdString().c_str(), nullptr);
                worksheet_write_string(ws, onRow, 10, stigqterName.toStdString().c_str(), nullptr);
                worksheet_write_string(ws, onRow, 11, "Ongoing", nullptr);
                worksheet_write_string(ws, onRow, 12, "CCIs are self-assessed as non-compliant.", nullptr);
                worksheet_write_string(ws, onRow, 15, "Low", nullptr);
                worksheet_write_string(ws, onRow, 17, "Low", nullptr);
                worksheet_write_string(ws, onRow, 18, "Low", nullptr);
                worksheet_write_string(ws, onRow, 20, "Low", nullptr);

                ++onRow;
            }
            Q_EMIT progress(-1);
        }

    }

    Q_EMIT updateStatus(QStringLiteral("Writing workbook…"));

    //filter on column 1
    worksheet_autofilter(ws, 6, 0, onRow-1, 21);

    //close and write the workbook
    workbook_close(wb);

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
