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

#include "workerhtml.h"

#include "dbmanager.h"
#include "stig.h"

#include <QDir>

/**
 * @class WorkerHTML
 * @brief Often, systems are reliant on manual data entry and
 * management solutions. To aide in this, this worker process is used
 * to create HTML-formatted checklists for a hard-copy of the STIG
 * requirements.
 *
 * Only static, well-formatted HTML is created.
 */

/**
 * @brief WorkerHTML::WorkerHTML
 * @param parent
 *
 * Main constructor.
 */
WorkerHTML::WorkerHTML(QObject *parent) : QObject(parent)
{
}

/**
 * @brief WorkerHTML::SetDir
 * @param dir
 *
 * Sets the output directory of the routine to @a dir.
 */
void WorkerHTML::SetDir(const QString &dir)
{
    _exportDir = dir;
}

/**
 * @brief WorkerHTML::process
 *
 * Perform the operations of this worker process.
 *
 * @example process
 * @title process
 *
 * This function should be kicked off as a background task. It emits
 * signals that describe its progress and state.
 *
 * @code
 * QThread *thread = new QThread;
 * WorkerHTML *html = new WorkerHTML();
 * html->SetDir(dir); // "dir" is a path to the export directory
 * connect(thread, SIGNAL(started()), html, SLOT(process())); // Start the worker when the new thread emits its started() signal.
 * connect(html, SIGNAL(finished()), thread, SLOT(quit())); // Kill the thread once the worker emits its finished() signal.
 * connect(thread, SIGNAL(finished()), this, SLOT(EndFunction()));  // execute some EndFunction() (custom code) when the thread is cleaned up.
 * connect(html, SIGNAL(initialize(int, int)), this, SLOT(Initialize(int, int))); // If progress status is needed, connect a custom Initialize(int, int) function to the initialize slot.
 * connect(html, SIGNAL(progress(int)), this, SLOT(Progress(int))); // If progress status is needed, connect the progress slot to a custom Progress(int) function.
 * connect(html, SIGNAL(updateStatus(QString)), ui->lblStatus, SLOT(setText(QString))); // If progress status is needed, connect a human-readable display of the status to the updateStatus(QString) slot.
 * t->start(); // Start the thread
 *
 * //Don't forget to handle the *t and *addAsset cleanup!
 * @endcode
 */
void WorkerHTML::process()
{
    DbManager db;

    //Load the STIG checks into memory
    emit initialize(1, 0);
    emit updateStatus(QStringLiteral("Loading STIG information into memory…"));
    QList<STIG> stigs = db.GetSTIGs();

    QMap<STIG, QList<STIGCheck>> checkMap;
    int count = 0;
    foreach (const STIG &s, db.GetSTIGs())
    {
        QList<STIGCheck> checks = s.GetSTIGChecks();
        count += checks.count();
        checkMap.insert(s, checks);
    }

    //update progress bar to reflect number of steps
    emit initialize(1 + checkMap.count() + count, 1);

    QDir outputDir(_exportDir);
    QFile main(outputDir.filePath("main.html"));
    main.open(QIODevice::WriteOnly);
    QString headerExtra = db.GetVariable("HTMLHeader");

    main.write("<!doctype html>"
               "<html lang=\"en\">"
               "<head>"
               "<meta charset=\"utf-8\">"
               "<title>STIGQter: STIG Summary</title>");
    main.write(headerExtra.toStdString().c_str());
    main.write("</head>"
               "<body>"
               "<h1><a href=\"https://www.stigqter.com/\">STIGQter</a>: STIG Summary</h1>"
               "<ul>");

    foreach (const STIG &s, checkMap.keys())
    {
        QString STIGName = PrintSTIG(s);
        QString STIGFileName = s.fileName;
        STIGFileName = STIGFileName.replace(".xml", ".html", Qt::CaseInsensitive);
        emit updateStatus("Creating page for " + STIGName + "…");
        main.write("<li><a href=\"");
        main.write(STIGFileName.toStdString().c_str());
        main.write("\">");
        main.write(STIGName.toStdString().c_str());
        main.write("</li>");

        QFile stig(outputDir.filePath(STIGFileName));
        stig.open(QIODevice::WriteOnly);

        stig.write("<!doctype html>"
                   "<html lang=\"en\">"
                   "<head>"
                   "<meta charset=\"utf-8\">"
                   "<title>STIGQter: STIG Details: ");
        stig.write(STIGName.toStdString().c_str());
        stig.write("</title>");
        stig.write(headerExtra.toStdString().c_str());
        stig.write("</head>"
                   "<body>"
                   "<h1>"
                   "<a href=\"https://www.stigqter.com/\">STIGQter</a>: <a href=\"main.html\">STIG Summary</a>: ");
        stig.write(s.title.toStdString().c_str());
        stig.write("</h1><h2>Version: ");
        stig.write(QString::number(s.version).toStdString().c_str());
        stig.write("</h2>"
                   "<h2>");
        stig.write(QString(s.release).toStdString().c_str());
        stig.write("</h2>"
                   "<table border=\"1\">"
                   "<tr>"
                   "<th>Checked</th>"
                   "<th>Name</th>"
                   "<th>Title</th>"
                   "</tr>");

        foreach (const STIGCheck &c, checkMap[s])
        {
            QString checkName(PrintSTIGCheck(c));
            stig.write("<tr>"
                       "<td>☐</td>"
                       "<td style=\"white-space:nowrap;\">"
                       "<a href=\"");
            stig.write(checkName.toStdString().c_str());
            stig.write(".html\">");
            stig.write(checkName.toStdString().c_str());
            stig.write("</a>"
                       "</td>"
                       "<td>");
            stig.write(c.title.toStdString().c_str());
            stig.write("</td>"
                       "</tr>");

            QFile check(outputDir.filePath(checkName + ".html"));
            check.open(QIODevice::WriteOnly);
            check.write("<!doctype html>"
                       "<html lang=\"en\">"
                       "<head>"
                       "<meta charset=\"utf-8\">"
                       "<title>STIGQter: STIG Check Details: ");
            check.write(checkName.toStdString().c_str());
            check.write(": ");
            check.write(c.title.toStdString().c_str());
            check.write("</title>");
            check.write(headerExtra.toStdString().c_str());
            check.write("</head>"
                       "<body>"
                       "<h1>"
                       "<a href=\"https://www.stigqter.com/\">STIGQter</a>: <a href=\"main.html\">STIG Summary</a>: <a href=\"");
            check.write(STIGFileName.toStdString().c_str());
            check.write("\">");
            check.write(STIGName.toStdString().c_str());
            check.write("</a>"
                        ": ");
            check.write(c.title.toStdString().c_str());
            check.write("</h1>"
                        "<h2>DISA Rule</h2>"
                        "<p>");
            check.write(c.rule.toStdString().c_str());
            check.write("</p>"
                        "<h2>Vulnerability Number</h2>"
                        "<p>");
            check.write(c.vulnNum.toStdString().c_str());
            check.write("</p>"
                        "<h2>Group Title</h2>"
                        "<p>");
            check.write(c.groupTitle.toStdString().c_str());
            check.write("</p>"
                        "<h2>Rule Version</h2>"
                        "<p>");
            check.write(c.ruleVersion.toStdString().c_str());
            check.write("</p>"
                        "<h2>Severity</h2>"
                        "<p>");
            check.write(GetSeverity(c.severity).toStdString().c_str());
            check.write("</p>");
            CCI cci = c.GetCCI();
            if (cci.id >= 0)
            {
                check.write("<h2>Control Correlation Identifier (CCI)</h2>"
                            "<p>");
                check.write(PrintCCI(cci).toStdString().c_str());
                check.write("</p>"
                            "<h2>CCI Definition</h2>"
                            "<p>");
                check.write(cci.definition.toStdString().c_str());
                check.write("</p>");
            }
            check.write("<h2>Weight</h2>"
                        "<p>");
            check.write(QString::number(c.weight).toStdString().c_str());
            check.write("</p>"
                        "<h2>False Positives</h2>"
                        "<p>");
            check.write(c.falsePositives.toStdString().c_str());
            check.write("</p>"
                        "<h2>False Negatives</h2>"
                        "<p>");
            check.write(c.falseNegatives.toStdString().c_str());
            check.write("</p>"
                        "<h2>Fix Recommendation</h2>"
                        "<p>");
            check.write(c.fix.toStdString().c_str());
            check.write("</p>"
                        "<h2>Check Contents</h2>"
                        "<p>");
            check.write(c.check.toStdString().c_str());
            check.write("</p>"
                        "<h2>Documentable</h2>"
                        "<p>");
            check.write(c.documentable ? "True" : "False");
            check.write("</p>"
                        "<h2>Rule Version</h2>"
                        "<p>");
            check.write(c.ruleVersion.toStdString().c_str());
            check.write("</p>"
                        "<h2>Mitigations</h2>"
                        "<p>");
            check.write(c.mitigations.toStdString().c_str());
            check.write("</p>"
                        "<h2>Severity Override Guidance</h2>"
                        "<p>");
            check.write(c.severityOverrideGuidance.toStdString().c_str());
            check.write("</p>"
                        "<h2>Check Content Reference</h2>"
                        "<p>");
            check.write(c.checkContentRef.toStdString().c_str());
            check.write("</p>"
                        "<h2>Potential Impact</h2>"
                        "<p>");
            check.write(c.potentialImpact.toStdString().c_str());
            check.write("</p>"
                        "<h2>Third-Party Tools</h2>"
                        "<p>");
            check.write(c.thirdPartyTools.toStdString().c_str());
            check.write("</p>"
                        "<h2>Mitigation Control</h2>"
                        "<p>");
            check.write(c.mitigationControl.toStdString().c_str());
            check.write("</p>"
                        "<h2>Responsibility</h2>"
                        "<p>");
            check.write(c.responsibility.toStdString().c_str());
            check.write("</p>"
                        "<h2>IA Controls</h2>"
                        "<p>");
            check.write(c.iaControls.toStdString().c_str());
            check.write("</p>"
                        "<h2>Target Key</h2>"
                        "<p>");
            check.write(c.targetKey.toStdString().c_str());
            check.write("</p>"
                        "</body>"
                        "</html>");
            check.close();

            emit progress(-1);
        }
        emit progress(-1);
        stig.write("</table>"
                   "</body>"
                   "</html>");
        stig.close();
    }

    main.write("</ul>"
               "</body>"
               "</html>");
    main.close();

    emit finished();
}
