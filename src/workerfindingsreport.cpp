/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2023 Jon Hood, http://www.hoodsecurity.com/
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

#include <algorithm>
#include <cstdio>
#include <string>

/**
 * @class WorkerFindingsReport
 * @brief Export a human-readable detailed findings report. This
 * report is a workbook in .xlsx format with two worksheets:
 * @list
 * @li The first sheet is a detailed list of all @a CKLChecks that
 * have been imported.
 * @li The second sheet details the RMF @a Controls, their highest-
 * watermark @a Severity for every non-compliant @a CCI, and a
 * summary of each @a CKLCheck that is non-compliant under that
 * @a CCI.
 *
 * This report is generally  used when performing on-site validations
 * to help management understand the "big picture" of what needs to
 * be fixed on their system.
 */

/**
 * @brief WorkerFindingsReport::WorkerFindingsReport
 * @param parent
 *
 * Default constructor.
 */
WorkerFindingsReport::WorkerFindingsReport(QObject *parent) : Worker(parent), _fileName()
{
}

/**
 * @brief WorkerFindingsReport::SetReportName
 * @param fileName
 *
 * Set the name of the output file before writing to it.
 */
void WorkerFindingsReport::SetReportName(const QString &fileName)
{
    _fileName = fileName;
}

/**
 * @brief WorkerFindingsReport::process
 *
 * This background worker uses the suplied fileName (see
 * SetReportName()) to output the workbook into .xlsx format.
 * Libxlsxwriter is used to generate this report.
 */
void WorkerFindingsReport::process()
{
    Worker::process();

    DbManager db;

    QMap<CCI, QVector<CKLCheck>> failedCCIs;
    QVector<CKLCheck> checks = db.GetCKLChecks();
    int numChecks = checks.count();
    Q_EMIT initialize(numChecks+3, 0);

    //new workbook
    lxw_workbook  *wb = workbook_new(_fileName.toStdString().c_str());

    //2 sheets - findings and controls
    lxw_worksheet *wsFindings = workbook_add_worksheet(wb, "Findings");
    lxw_worksheet *wsCCIs = workbook_add_worksheet(wb, "CCIs");
    lxw_worksheet *wsControls = workbook_add_worksheet(wb, "Controls");

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
    worksheet_write_string(wsFindings, 0, 4, "Control", fmtBold);
    worksheet_set_column(wsFindings, 5, 5, 10, nullptr);
    worksheet_write_string(wsFindings, 0, 5, "CCI", fmtBold);
    worksheet_set_column(wsFindings, 6, 6, 30, nullptr);
    worksheet_write_string(wsFindings, 0, 6, "STIG/SRG", fmtBold);
    worksheet_set_column(wsFindings, 7, 7, 18, nullptr);
    worksheet_write_string(wsFindings, 0, 7, "Rule", fmtBold);
    worksheet_set_column(wsFindings, 8, 8, 30, nullptr);
    worksheet_write_string(wsFindings, 0, 8, "Title", fmtBold);
    worksheet_write_string(wsFindings, 0, 9, "Vuln", fmtBold);
    worksheet_write_string(wsFindings, 0, 10, "Discussion", fmtBold);
    worksheet_write_string(wsFindings, 0, 11, "Fix", fmtBold);
    worksheet_write_string(wsFindings, 0, 12, "Finding Details", fmtBold);
    worksheet_write_string(wsFindings, 0, 13, "Comments", fmtBold);

    //write headers for CCI findings
    worksheet_write_string(wsCCIs, 0, 0, "Control", fmtBold);
    worksheet_set_column(wsCCIs, 1, 1, 10, nullptr);
    worksheet_write_string(wsCCIs, 0, 1, "CCI", fmtBold);
    worksheet_write_string(wsCCIs, 0, 2, "Severity", fmtBold);
    worksheet_write_string(wsCCIs, 0, 3, "Checks", fmtBold);
    worksheet_set_column(wsCCIs, 3, 3, 30.86, fmtBold);
    worksheet_write_string(wsCCIs, 0, 4, "Recommended Fixes", fmtBold);
    worksheet_set_column(wsCCIs, 4, 4, 30.86, fmtBold);

    //write headers for Controls
    worksheet_write_string(wsControls, 0, 0, "Control", fmtBold);
    worksheet_set_column(wsControls, 1, 1, 50, nullptr);
    worksheet_write_string(wsControls, 0, 1, "Compliance Status", fmtBold);
    worksheet_write_string(wsControls, 0, 2, "Control Technical Deficiency Description", fmtBold);
    worksheet_set_column(wsControls, 2, 2, 50, nullptr);
    worksheet_write_string(wsControls, 0, 3, "Control Technical Recommendations", fmtBold);
    worksheet_set_column(wsControls, 3, 3, 50, nullptr);

    //write each failed check
    unsigned int onRow = 0;
    for (int i = 0; i < numChecks; i++)
    {
        CKLCheck cc = checks[i];
        STIGCheck sc = cc.GetSTIGCheck();
        QVector<CCI> ccis = sc.GetCCIs();
        Asset a = cc.GetAsset();
        Status s = cc.status;
        Q_EMIT updateStatus("Adding " + PrintAsset(a) + ", " + PrintSTIGCheck(sc) + "…");
        int findingNumber = 0;
        Q_FOREACH (CCI c, ccis)
        {
            onRow++;
            findingNumber++;
            int divisor = QString::number(findingNumber).length() * 10;
            //internal id
            worksheet_write_number(wsFindings, onRow, 0, (double) cc.id + ((double) findingNumber / (double) divisor), nullptr);
            //host
            worksheet_write_string(wsFindings, onRow, 1, a.hostName.toStdString().c_str(), nullptr);
            //status
            worksheet_write_string(wsFindings, onRow, 2, GetStatus(s).toStdString().c_str(), nullptr);
            //severity
            worksheet_write_string(wsFindings, onRow, 3, GetSeverity(cc.GetSeverity()).toStdString().c_str(), nullptr);
            //control
            worksheet_write_string(wsFindings, onRow, 4, PrintControl(c.GetControl()).toStdString().c_str(), nullptr);
            //cci
            worksheet_write_number(wsFindings, onRow, 5, c.cci, fmtCci);
            //STIG/SRG
            worksheet_write_string(wsFindings, onRow, 6, Excelify(PrintSTIG(sc.GetSTIG())).toStdString().c_str(), nullptr);
            //rule
            worksheet_write_string(wsFindings, onRow, 7, Excelify(sc.rule).toStdString().c_str(), nullptr);
            //rule title
            worksheet_write_string(wsFindings, onRow, 8, Excelify(sc.title).toStdString().c_str(), nullptr);
            //vuln
            worksheet_write_string(wsFindings, onRow, 9, Excelify(sc.vulnNum).toStdString().c_str(), nullptr);
            //discussion
            worksheet_write_string(wsFindings, onRow, 10, Excelify(sc.vulnDiscussion).toStdString().c_str(), nullptr);
            //fix text
            worksheet_write_string(wsFindings, onRow, 11, Excelify(sc.fix).toStdString().c_str(), nullptr);
            //details
            worksheet_write_string(wsFindings, onRow, 12, Excelify(cc.findingDetails).toStdString().c_str(), nullptr);
            //comments
            worksheet_write_string(wsFindings, onRow, 13, Excelify(cc.comments).toStdString().c_str(), nullptr);

            //if the check is a finding, add it to the CCI sheet
            if (s == Status::Open)
            {
                if (failedCCIs.contains(c))
                    failedCCIs[c].append(cc);
                else
                    failedCCIs.insert(c, {cc});
            }
        }
        Q_EMIT progress(-1);
    }

    Q_EMIT initialize(numChecks+failedCCIs.count()*2+1, numChecks);

    onRow = 0;
    QMap<Control, QVector<CCI>> failedControls;
    auto ccis = db.GetCCIs();
    for (auto i = ccis.constBegin(); i != ccis.constEnd(); i++)
    {
        if (failedCCIs.contains(*i))
            continue;
        if (i->importCompliance2.compare(QStringLiteral("non-compliant"), Qt::CaseSensitivity::CaseInsensitive) == 0)
        {
            failedCCIs.insert(*i, {});
        }
    }
    for (auto i = failedCCIs.constBegin(); i != failedCCIs.constEnd(); i++)
    {
        onRow++;
        CCI c = i.key();
        Q_EMIT updateStatus("Adding " + PrintCCI(c) + "…");
        QVector<CKLCheck> checks2 = i.value();
        if (checks2.count() > 1)
            std::sort(checks2.begin(), checks2.end());
        Control control = c.GetControl();

        //build failed Control list
        if (!failedControls.contains(control))
        {
            failedControls.insert(control, {c});
        }
        else
        {
            failedControls[control].append(c);
        }

        //control
        worksheet_write_string(wsCCIs, onRow, 0, PrintControl(control).toStdString().c_str(), nullptr);
        //cci
        worksheet_write_number(wsCCIs, onRow, 1, c.cci, fmtCci);
        //severity
        if (checks2.isEmpty())
            worksheet_write_string(wsCCIs, onRow, 2, GetSeverity(Severity::low).toStdString().c_str(), nullptr);
        else
            worksheet_write_string(wsCCIs, onRow, 2, GetSeverity(checks2.first().GetSeverity()).toStdString().c_str(), nullptr);
        //Checks
        QString assets = QString();
        QString fixes = QString();
        if (checks2.isEmpty())
            assets.append(QStringLiteral("Imported/Documentation Findings"));
        QList<STIGCheck> completedChecks;
        Q_FOREACH (CKLCheck cc, checks2)
        {
            STIGCheck sc = cc.GetSTIGCheck();
            if (completedChecks.contains(sc))
                continue;
            completedChecks.append(sc);

            //start a new line if the field already has text
            if (!assets.isEmpty())
                assets.append(QStringLiteral("\n"));
            if (!fixes.isEmpty() && !sc.fix.trimmed().isEmpty())
                fixes.append(QStringLiteral("\n"));

            int nf = 0; //not a finding
            int f = 0; //finding
            QVector<CKLCheck> checks3 = db.GetCKLChecks(sc);
            Q_FOREACH(CKLCheck c3, checks3)
            {
                if (c3.status == Status::NotAFinding)
                    nf++;
                else if (c3.status == Status::Open)
                    f++;
            }
            QString samples = QString(" (Occurred on %1 of %2 samples: %3%)").arg(QString::number(f), QString::number(f + nf), QString::number((double)100 * (double)f / (double)(f + nf), 'f', 2));
            assets.append(PrintCKLCheck(cc) + samples);
            if (!sc.fix.trimmed().isEmpty())
            {
                if (!fixes.isEmpty())
                    fixes.append("\n\n");
                fixes.append("-----" + sc.rule + "-----\n");
                fixes.append(sc.fix);
            }
        }
        if (fixes.length() > 2500)
        {
            fixes.truncate(2488);
            fixes.append("(truncated)");
        }
        worksheet_write_string(wsCCIs, onRow, 3, assets.toStdString().c_str(), fmtWrapped);
        worksheet_write_string(wsCCIs, onRow, 4, fixes.toStdString().c_str(), fmtWrapped);
        Q_EMIT progress(-1);
    }

    // build non-compliant Controls worksheet
    onRow = 0;
    for (auto i = failedControls.constBegin(); i != failedControls.constEnd(); i++)
    {
        Q_EMIT updateStatus("Adding " + PrintControl(i.key()) + "…");
        onRow++;
        worksheet_write_string(wsControls, onRow, 0, PrintControl(i.key()).toStdString().c_str(), fmtWrapped);
        QString preamble = QStringLiteral("The following CCI");
        if (i.value().count() > 1)
        {
            preamble = preamble + QStringLiteral("s are");
        }
        else
        {
            preamble = preamble + QStringLiteral(" is");
        }
        preamble = preamble + QStringLiteral(" found to be non-compliant:");
        bool notFirst = false;
        QString technicalDesc = QString();
        QString technicalRec = QString();
        QVector<STIGCheck> failedChecksDup;
        for (auto j = i.value().constBegin(); j != i.value().constEnd(); j++)
        {
            Q_EMIT progress(-1);
            if (failedCCIs.contains(*j))
            {
                auto failedChecks = failedCCIs.value(*j);
                for (auto k = failedChecks.constBegin(); k != failedChecks.constEnd(); k++)
                {
                    auto sc = k->GetSTIGCheck();
                    if (failedChecksDup.contains(sc))
                        continue;
                    failedChecksDup.push_back(sc);
                }
            }
            if (notFirst)
                preamble = preamble + QStringLiteral(",");
            preamble = preamble + QStringLiteral(" ") + PrintCCI(*j);
            notFirst = true;
        }
        for (auto sc2 = failedChecksDup.constBegin(); sc2 != failedChecksDup.constEnd(); sc2++)
        {
            //calculate amount of text allowed for each entry
            auto numFailure = failedChecksDup.count();
            if (numFailure > 0)
            {
                auto width = (2472 / numFailure) - (13 + sc2->rule.length());
                if (technicalDesc.isEmpty())
                    technicalDesc = QStringLiteral("Technical Vulnerabilities:");
                technicalDesc += "\n\n-----" + sc2->rule + "-----\n";
                if (width > 15)
                {
                    QString tmpVulnDisc = sc2->vulnDiscussion;
                    if (tmpVulnDisc.length() > width)
                    {
                        tmpVulnDisc.truncate(width - 11);
                        tmpVulnDisc += "(truncated)";
                    }
                    technicalDesc += tmpVulnDisc;
                }
                if (technicalRec.isEmpty())
                    technicalRec = QStringLiteral("Technical Recommendations:");
                technicalRec += "\n\n-----" + sc2->rule + "-----\n";
                if (width > 15)
                {
                    QString tmpVulnFix = sc2->fix;
                    if (tmpVulnFix.length() > width)
                    {
                        tmpVulnFix.truncate(width - 11);
                        tmpVulnFix += "(truncated)";
                    }
                    technicalRec += tmpVulnFix;
                }
            }
        }
        worksheet_write_string(wsControls, onRow, 1, preamble.toStdString().c_str(), fmtWrapped);
        if (technicalDesc.isEmpty())
            technicalDesc = QStringLiteral("Documentation Deficiency");
        if (technicalDesc.length() > 2500)
        {
            technicalDesc.truncate(2386);
            technicalDesc += QStringLiteral("\nThis has been truncated due to character limitations; please, see the STIG Checklist files for more information.");
        }
        worksheet_write_string(wsControls, onRow, 2, technicalDesc.toStdString().c_str(), fmtWrapped);
        if (technicalRec.isEmpty())
            technicalRec = QStringLiteral("Documentation Deficiency");
        if (technicalRec.length() > 4900)
        {
            technicalRec.truncate(4786);
            technicalRec += QStringLiteral("\nThis has been truncated due to character limitations; please, see the STIG Checklist files for more information.");
        }
        worksheet_write_string(wsControls, onRow, 3, technicalRec.toStdString().c_str(), fmtWrapped);
    }

    Q_EMIT updateStatus(QStringLiteral("Writing workbook…"));

    //close and write the workbook
    workbook_close(wb);

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
