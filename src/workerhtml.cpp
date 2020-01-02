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

#include "workerhtml.h"

#include "dbmanager.h"
#include "stig.h"

#include <QDir>
#include <QList>
#include <QMap>
#include <QVariant>

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
 * @brief WorkerHTML::CheckItem
 * @param title
 * @param contents
 * @return An HTML-formatted section within the @a STIGCheck file
 * detailing the @a contents, but only when @a contents exist.
 */
QString WorkerHTML::CheckItem(const QString &title, const QString &contents)
{
    QString ret = QLatin1String();
    if (!contents.isNull() && !contents.isEmpty())
    {
        ret.append("<h2>" + title + "</h2><p>" + contents + "</p>");
    }
    return ret;
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
 * @example WorkerHTML::process
 * @title WorkerHTML::process
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
 * //Don't forget to handle the *thread and *html cleanup!
 * @endcode
 */
void WorkerHTML::process()
{
    DbManager db;

    //Load the STIG checks into memory
    Q_EMIT initialize(1, 0);
    Q_EMIT updateStatus(QStringLiteral("Loading STIG information into memory…"));
    QList<STIG> stigs = db.GetSTIGs();

    QMap<STIG, QList<STIGCheck>> checkMap;
    int count = 0;
    Q_FOREACH (const STIG &s, stigs)
    {
        QList<STIGCheck> checks = s.GetSTIGChecks();
        count += checks.count();
        checkMap.insert(s, checks);
    }

    //update progress bar to reflect number of steps
    Q_EMIT initialize(1 + checkMap.count() + count, 1);

    QDir outputDir(_exportDir);
    QFile main(outputDir.filePath(QStringLiteral("main.html")));
    main.open(QIODevice::WriteOnly);
    QString headerExtra = db.GetVariable(QStringLiteral("HTMLHeader"));

    main.write("<!doctype html>"
               "<html lang=\"en\">"
               "<head>"
               "<meta charset=\"utf-8\">"
               "<title>STIGQter: STIG Summary</title>");
    main.write(headerExtra.toStdString().c_str());
    main.write("</head>"
               "<body>"
               "<h1><img src=\"STIGQter.svg\" alt=\"STIGQter\" style=\"height:1em;\" /> <a href=\"https://www.stigqter.com/\">STIGQter</a>: STIG Summary</h1>"
               "<ul>");

    Q_FOREACH (const STIG &s, checkMap.keys())
    {
        QString STIGName = PrintSTIG(s);
        QString STIGFileName = s.fileName;
        STIGFileName = STIGFileName.replace(QStringLiteral(".xml"), QStringLiteral(".html"), Qt::CaseInsensitive);
        Q_EMIT updateStatus("Creating page for " + STIGName + "…");
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
                   "<h1><img src=\"STIGQter.svg\" alt=\"STIGQter\" style=\"height:1em;\" /> "
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

        Q_FOREACH (const STIGCheck &c, checkMap[s])
        {
            QString checkName(PrintSTIGCheck(c));
            Q_EMIT updateStatus("Creating Check " + checkName + "…");
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
                       "<h1><img src=\"STIGQter.svg\" alt=\"STIGQter\" style=\"height:1em;\" /> "
                       "<a href=\"https://www.stigqter.com/\">STIGQter</a>: <a href=\"main.html\">STIG Summary</a>: <a href=\"");
            check.write(STIGFileName.toStdString().c_str());
            check.write("\">");
            check.write(STIGName.toStdString().c_str());
            check.write("</a>"
                        ": ");
            check.write(c.title.toStdString().c_str());
            check.write("</h1>");
            check.write(CheckItem(QStringLiteral("DISA Rule"), c.rule).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Vulnerability Number"), c.vulnNum).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Group Title"), c.groupTitle).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Rule Version"), c.ruleVersion).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Severity"), GetSeverity(c.severity)).toStdString().c_str());
            QList<CCI> ccis = c.GetCCIs();
            if (ccis.count() > 0)
            {
                Q_FOREACH (CCI cci, ccis)
                {
                    check.write(CheckItem(QStringLiteral("Control Correlation Identifier (CCI)"), PrintCCI(cci)).toStdString().c_str());
                    check.write(CheckItem(QStringLiteral("CCI Definition"), cci.definition).toStdString().c_str());
                }
            }
            check.write(CheckItem(QStringLiteral("Weight"), QString::number(c.weight)).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("False Positives"), c.falsePositives).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("False Negatives"), c.falseNegatives).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Fix Recommendation"), c.fix).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Check Contents"), c.check).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Vulnerability Number"), c.vulnNum).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Documentable"), c.documentable ? QStringLiteral("True") : QStringLiteral("False")).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Rule Version"), c.ruleVersion).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Mitigations"), c.mitigations).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Severity Override Guidance"), c.check).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Check Content Reference"), c.checkContentRef).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Potential Impact"), c.potentialImpact).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Third-Party Tools"), c.thirdPartyTools).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Mitigation Control"), c.mitigationControl).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Responsibility"), c.responsibility).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("IA Controls"), c.iaControls).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Target Key"), c.targetKey).toStdString().c_str());
            check.write("</body>"
                        "</html>");
            check.close();

            Q_EMIT progress(-1);
        }
        Q_EMIT progress(-1);
        stig.write("</table>"
                   "</body>"
                   "</html>");
        stig.close();
    }

    main.write("</ul>"
               "</body>"
               "</html>");
    main.close();

    QFile svg(outputDir.filePath(QStringLiteral("STIGQter.svg")));
    svg.open(QIODevice::WriteOnly);
    svg.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
              "<svg width=\"6.2129mm\" height=\"8.3859mm\" version=\"1.1\" viewBox=\"0 0 6.2129421 8.3859148\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:cc=\"http://creativecommons.org/ns#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">"
              "<metadata>"
              "<rdf:RDF>"
              "<cc:Work rdf:about=\"\">"
              "<dc:format>image/svg+xml</dc:format>"
              "<dc:type rdf:resource=\"http://purl.org/dc/dcmitype/StillImage\"/>"
              "<dc:title/>"
              "</cc:Work>"
              "</rdf:RDF>"
              "</metadata>"
              "<g transform=\"translate(-72.489 -97.015)\">"
              "<path d=\"m78.579 98.032c-2.4522 0-2.867-0.9308-2.8707-0.93954-0.01799-0.04551-0.06244-0.07594-0.11271-0.07699h-0.0021c-0.04868 0-0.09366 0.03043-0.11324 0.07488-0.0029 0.0098-0.42677 0.94165-2.8697 0.94165-0.06826 0-0.12224 0.0553-0.12224 0.12197v4.1709c0 1.7074 2.9326 3.0118 3.0567 3.0665 0.0164 7e-3 0.03201 0.01 0.04974 0.01 0.01614 0 0.0336-3e-3 0.04921-0.01 0.12515-0.0548 3.0573-1.3592 3.0573-3.0665v-4.1709c-5.29e-4 -0.06668-0.05477-0.12197-0.12224-0.12197zm-0.55245 4.0502c0 1.3359-2.2961 2.358-2.3937 2.4003-0.01191 6e-3 -0.02593 8e-3 -0.03836 8e-3 -0.01349 0-0.02593-2e-3 -0.03863-8e-3 -0.09657-0.0423-2.3934-1.0644-2.3934-2.4003v-3.2647c0-0.05265 0.0426-0.09604 0.09578-0.09604 1.9127 0 2.2442-0.72919 2.2474-0.73634 0.01508-0.03519 0.05001-0.059 0.08837-0.059h0.0016c0.03916 5.29e-4 0.07382 0.02434 0.08784 0.06059 0.0032 0.0066 0.32808 0.73475 2.2474 0.73475 0.05318 0 0.09551 0.04339 0.09551 0.09604z\" stroke-width=\".26458\"/>"
              "<path d=\"m74.204 99.874c0.19818-0.13111 0.44325-0.16425 0.67627-0.16215 0.22189 3e-3 0.45478 0.0416 0.63868 0.17407 0.1336 0.0939 0.22044 0.23892 0.27834 0.38891 0.09365 0.24625 0.12116 0.51215 0.1243 0.77385 3.9e-4 0.26354-0.01153 0.53284-0.09876 0.78394-0.05842 0.1708-0.16962 0.32248-0.31632 0.42779 0.10557 0.17106 0.21324 0.34082 0.31881 0.51188-0.13269 0.0612-0.26498 0.12273-0.3978 0.18364-0.11304-0.18652-0.22555-0.37343-0.33899-0.55969-0.15338 0.0251-0.3103 0.0232-0.46447 6e-3 -0.18469-0.0221-0.37291-0.0785-0.51542-0.20277-0.1095-0.0948-0.17827-0.22752-0.22529-0.36243-0.07702-0.22817-0.09771-0.47101-0.10125-0.71045-0.0018-0.25883 0.01467-0.52171 0.09274-0.77005 0.06038-0.18679 0.16032-0.37319 0.32916-0.4827z\" stroke-width=\".013098\"/>"
              "<path d=\"m76.454 99.866c0.13884-1.5e-4 0.27768-1.5e-4 0.41653 0 3.9e-4 0.18364-1.3e-4 0.36716 2.64e-4 0.5508 0.17748 2.6e-4 0.35496 0 0.53245 1.5e-4 -3e-3 0.11919-0.0063 0.23839-0.0097 0.35758-0.17735 3.6e-4 -0.35457-1.4e-4 -0.53192 2.7e-4 3.9e-4 0.301-9.22e-4 0.60199 6.38e-4 0.90299 0.0034 0.0824 0.0016 0.16937 0.03785 0.24547 0.02646 0.0587 0.09771 0.0737 0.15574 0.0757 0.10937-3.6e-4 0.21861-7e-3 0.32798-9e-3 0.0067 0.1095 0.0131 0.21913 0.01939 0.32863-0.21756 0.0366-0.44587 0.0803-0.66199 0.0119-0.09103-0.027-0.17591-0.0874-0.21285-0.17735-0.06615-0.15312-0.07152-0.32353-0.0744-0.48792-2.64e-4 -0.29694 0-0.59375-1.3e-4 -0.89068-0.0968-2.7e-4 -0.19359 1.4e-4 -0.29039-2.7e-4 -2.64e-4 -0.11906-2.64e-4 -0.23826 0-0.35745 0.0968-3.5e-4 0.19346 1.5e-4 0.29026-2.6e-4 3.9e-4 -0.18364-1.3e-4 -0.36716 2.64e-4 -0.5508z\" stroke-width=\".013098\"/>"
              "<path d=\"m74.704 100.09c0.13478-0.0175 0.27624-0.0128 0.40382 0.0381 0.10335 0.0409 0.1911 0.12091 0.23747 0.22229 0.07112 0.15365 0.09837 0.32327 0.11212 0.4908 0.01493 0.22293 0.01283 0.44796-0.01794 0.66959-0.02161 0.1319-0.05239 0.27087-0.14172 0.37487-0.09064 0.1044-0.2304 0.14919-0.36453 0.15967-0.14146 0.0104-0.29065 0-0.41836-0.0669-0.07453-0.0397-0.13779-0.10191-0.17473-0.17814-0.0448-0.0913-0.06942-0.19097-0.08671-0.29078-0.05213-0.31646-0.06471-0.64392 0.0065-0.95855 0.02934-0.11866 0.07204-0.24048 0.15875-0.32995 0.07545-0.0766 0.1805-0.11619 0.28528-0.13098z\" fill=\"#41cd52\" stroke-width=\".013098\"/>"
              "<path transform=\"scale(.26458)\" d=\"m283.93 393.97c-3.5766-2.0431-5.8247-4.0544-6.7559-6.0442l-0.5337-1.1405 0.0468-6.7724 0.0468-6.7724 1.7916-0.11901c3.1128-0.20677 5.4845-1.0355 6.5604-2.2924l0.59365-0.69354 0.68124 0.72338c1.2054 1.28 3.4587 2.053 6.5896 2.2609l1.8192 0.12074v13.75l-0.53571 1.0658c-0.9865 1.9627-4.0405 4.5763-7.1824 6.1467-0.61104 0.30542-1.2539 0.55471-1.4286 0.55398-0.17468-7.2e-4 -0.93657-0.35491-1.6931-0.78706zm2.5934-5.455c0.0806-0.0764-0.10722-0.55124-0.41733-1.0552l-0.56385-0.91637 0.46044-0.5472c0.75252-0.89432 1.0514-2.26 0.94999-4.3412-0.10997-2.2576-0.35166-3.0537-1.1779-3.8799-1.658-1.658-5.3935-1.1934-6.3336 0.78766-0.49354 1.04-0.70225 2.4461-0.61388 4.1356 0.16567 3.1672 1.2492 4.3816 3.9092 4.3816 0.89481 0 1.068 0.0556 1.2515 0.40179 0.11715 0.22098 0.39998 0.69954 0.62851 1.0635l0.4155 0.66169 0.67242-0.27647c0.36983-0.15206 0.73835-0.33897 0.81893-0.41535zm6.0142-2.328v-0.71429h-0.79729c-1.0577 0-1.167-0.24134-1.167-2.5776v-1.8867h1.9268l0.069-0.72356c0.038-0.39796 0.033-0.75957-0.011-0.80357s-0.50858-0.08-1.0324-0.08h-0.95238v-1.9643h-1.6071v1.9643h-0.625c-0.62169 0-0.625 4e-3 -0.625 0.80357 0 0.79932 3e-3 0.80357 0.625 0.80357h0.625v2.313c0 3.2655 0.18597 3.5459 2.3661 3.5678l1.2054 0.0121z\" fill=\"#41cd52\" stroke-width=\".17857\"/>"
              "</g>"
              "</svg>");
    svg.close();

    Q_EMIT finished();
}
