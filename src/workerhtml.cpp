/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2019–2021 Jon Hood, http://www.hoodsecurity.com/
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
WorkerHTML::WorkerHTML(QObject *parent) : Worker(parent)
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
        ret.append("<h2>" + title.toHtmlEscaped() + "</h2><p>" + contents.toHtmlEscaped() + "</p>");
    }
    return Sanitize(ret);
}

/**
 * @brief WorkerHTML::CheckItem
 * @param title
 * @param contents
 * @return An HTML-formatted section within the @a STIGCheck file
 * detailing the @a contents, but only when @a contents exist.
 */
QString WorkerHTML::CheckItem(const QString &title, const QStringList &contents)
{
    QString ret = QLatin1String();
    if (contents.count() > 0)
    {
        ret.append("<h2>" + title.toHtmlEscaped() + "</h2><ul>");
        Q_FOREACH(const QString &content, contents)
        {
            ret.append("<li>" + content.toHtmlEscaped() + "</li>");
        }
        ret.append(QStringLiteral("</ul>"));
    }
    return Sanitize(ret);
}

/**
 * @brief WorkerHTML::Sanitize
 * @param contents
 * @return Better HTML formatting of newlines
 */
QString WorkerHTML::Sanitize(const QString &contents)
{
    if (contents.isEmpty())
        return contents;
    QString ret(contents);
    return ret.replace(QStringLiteral("\n"), QStringLiteral("<br />\n"));
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
    Worker::process();

    DbManager db;

    //Load the STIG checks into memory
    Q_EMIT initialize(1, 0);
    Q_EMIT updateStatus(QStringLiteral("Loading STIG information into memory…"));
    QVector<STIG> stigs = db.GetSTIGs();

    QMap<STIG, QVector<STIGCheck>> checkMap;
    int count = 0;
    Q_FOREACH (const STIG &s, stigs)
    {
        QVector<STIGCheck> checks = s.GetSTIGChecks();
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
    main.write("<link rel=\"icon\" type=\"image/svg+xml\" href=\"STIGQter.svg\" />");
    main.write(headerExtra.toStdString().c_str());
    main.write("</head>"
               "<body>"
               "<div><img src=\"STIGQter.svg\" alt=\"STIGQter\" style=\"height:1em;\" /> <a href=\"https://www.stigqter.com/\">STIGQter</a>:</div> <h1>STIG Summary</h1>"
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
        main.write("</a></li>");

        QFile stig(outputDir.filePath(STIGFileName));
        stig.open(QIODevice::WriteOnly);

        stig.write("<!doctype html>"
                   "<html lang=\"en\">"
                   "<head>"
                   "<meta charset=\"utf-8\">"
                   "<title>STIGQter: STIG Details: ");
        stig.write(STIGName.toStdString().c_str());
        stig.write("</title>");
        stig.write("<link rel=\"icon\" type=\"image/svg+xml\" href=\"STIGQter.svg\" />");
        stig.write(headerExtra.toStdString().c_str());
        stig.write("</head>"
                   "<body>"
                   "<div><img src=\"STIGQter.svg\" alt=\"STIGQter\" style=\"height:1em;\" /> "
                   "<a href=\"https://www.stigqter.com/\">STIGQter</a>: <a href=\"main.html\">STIG Summary</a>:</div> <h1>");
        stig.write(s.title.toStdString().c_str());
        stig.write("</h1><h2>Version: ");
        stig.write(QString::number(s.version).toStdString().c_str());
        stig.write("</h2>"
                   "<h2>");
        stig.write(QString(s.release).toStdString().c_str());
        stig.write("</h2>"
                   "<table style=\"border-collapse: collapse; border: 1px solid black;\">"
                   "<tr>"
                   "<th style=\"border: 1px solid black;\">Checked</th>"
                   "<th style=\"border: 1px solid black;\">Name</th>"
                   "<th style=\"border: 1px solid black;\">Title</th>"
                   "</tr>");

        Q_FOREACH (const STIGCheck &c, checkMap[s])
        {
            QString checkName(PrintSTIGCheck(c));
            Q_EMIT updateStatus("Creating Check " + checkName + "…");
            stig.write("<tr>"
                       "<td style=\"border: 1px solid black;\">☐</td>"
                       "<td style=\"border: 1px solid black; white-space: nowrap;\">"
                       "<a href=\"");
            stig.write(checkName.toStdString().c_str());
            stig.write(".html\">");
            stig.write(checkName.toStdString().c_str());
            stig.write("</a>"
                       "</td>"
                       "<td style=\"border: 1px solid black;\">");
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
            check.write("<link rel=\"icon\" type=\"image/svg+xml\" href=\"STIGQter.svg\" />");
            check.write(headerExtra.toStdString().c_str());
            check.write("</head>"
                       "<body>"
                       "<div><img src=\"STIGQter.svg\" alt=\"STIGQter\" style=\"height:1em;\" /> "
                       "<a href=\"https://www.stigqter.com/\">STIGQter</a>: <a href=\"main.html\">STIG Summary</a>: <a href=\"");
            check.write(STIGFileName.toStdString().c_str());
            check.write("\">");
            check.write(STIGName.toStdString().c_str());
            check.write("</a>"
                        ":</div> <h1>");
            check.write(c.title.toStdString().c_str());
            check.write("</h1>");
            check.write(CheckItem(QStringLiteral("DISA Rule"), c.rule).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Vulnerability Number"), c.vulnNum).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Group Title"), c.groupTitle).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Rule Version"), c.ruleVersion).toStdString().c_str());
            check.write(CheckItem(QStringLiteral("Severity"), GetSeverity(c.severity)).toStdString().c_str());
            QVector<CCI> ccis = c.GetCCIs();
            QStringList cciStr;
            if (ccis.count() > 0)
            {
                Q_FOREACH (CCI cci, ccis)
                {
                    cciStr.append(PrintCCI(cci) + " - " + cci.definition);
                }
            }
            check.write(CheckItem(QStringLiteral("CCI(s)"), cciStr).toStdString().c_str());
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
    svg.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
              "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">"
              "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" xmlns:serif=\"http://www.serif.com/\" width=\"100%\" height=\"100%\" viewBox=\"0 0 200 200\" version=\"1.1\" xml:space=\"preserve\" style=\"fill-rule:evenodd;clip-rule:evenodd;stroke-linejoin:round;stroke-miterlimit:2;\">"
              "<path d=\"M96.811,126.461c53.038,-67.257 49.958,-90.674 83.894,-85.511c-34.584,47.088 -46.567,66.713 -73.966,128.5l-9.928,-42.989Z\"/>"
              "<path d=\"M96.389,189.918c-15.558,-21.486 -33.377,-47.067 -59.228,-65.725c15.928,-2.634 24.927,-4.043 44.655,11.884c5.738,6.627 11.554,5.763 14.573,53.841Z\"/>"
              "<path d=\"M75.819,42.48c46.439,16.837 84.329,22.755 101.582,17.593c-3.873,11.242 -10.34,16.366 -8.151,33.728c-27.173,-6.625 -48.701,-5.615 -75.874,0c-1.274,-26.031 -10.43,-39.058 -17.557,-51.321Z\"/>"
              "<path d=\"M85.537,125.771l3.4,2.92c35.832,-68.049 70.548,-107.987 106.971,-121.27c0.235,-0.082 0.497,0.002 0.638,0.207c0.142,0.205 0.129,0.48 -0.031,0.67c-42.227,50.312 -76.735,107.201 -101.304,172.554c-7.075,-9.074 -14.287,-17.998 -21.693,-26.738c5.477,-7.456 9.688,-17.216 12.019,-28.343Z\" style=\"fill:#41cd52;\"/>"
              "<path d=\"M67.272,111.238c0.261,-2.075 0.395,-4.204 0.395,-6.382c0,-17.825 -8.991,-32.297 -20.066,-32.297c-7.848,0 -14.65,7.268 -17.927,17.859c-6.685,-2.715 -13.378,-4.851 -20.03,-6.38c5.349,-25.453 20.334,-43.776 37.957,-43.776c22.149,0 40.132,28.944 40.132,64.594c0,7.211 -0.736,14.148 -2.129,20.608l-0.067,0.307c-2.352,11.13 -6.546,20.89 -12.019,28.343l-0.164,0.224c-6.942,9.43 -15.938,15.112 -25.753,15.112c-22.149,0 -40.131,-28.943 -40.131,-64.594c0,-5.743 0.467,-11.312 1.387,-16.582l7.497,6.473l11.189,10.347c0.073,17.716 9.033,32.059 20.058,32.059c2.981,0 5.811,-1.048 8.359,-2.967l0.133,-0.099c5.645,-4.223 9.861,-12.583 11.154,-22.649l0.025,-0.2Z\"/>"
              "<path d=\"M8.857,88.274l-5.079,-4.386c-0.194,-0.16 -0.255,-0.431 -0.15,-0.659c0.105,-0.228 0.351,-0.357 0.599,-0.313c1.803,0.329 3.607,0.702 5.417,1.122l-0.369,1.619l-0.042,0.268l0.042,-0.268l0.369,-1.619c6.679,1.538 13.359,3.668 20.03,6.38c-0.099,0.312 -0.195,0.627 -0.287,0.945c0.092,-0.318 0.188,-0.633 0.287,-0.945c12.527,5.05 25.049,12.102 37.573,21.02c-1.3,10.135 -5.564,18.543 -11.287,22.748c-9.155,-10.061 -18.611,-19.79 -28.417,-29.092l-0.007,-0.238c0,-2.852 0.23,-5.619 0.665,-8.252c-0.435,2.633 -0.665,5.4 -0.665,8.252l0.007,0.238l-11.189,-10.347l-7.497,-6.473Zm19.515,7.36c-0.049,0.265 -0.097,0.532 -0.142,0.801c0.039,-0.231 0.079,-0.461 0.122,-0.69l0.02,-0.111Zm0.18,-0.913c-0.055,0.268 -0.109,0.537 -0.16,0.808c0.051,-0.271 0.105,-0.54 0.16,-0.808Zm0.328,-1.455c-0.089,0.364 -0.173,0.731 -0.253,1.101c0.08,-0.37 0.164,-0.737 0.253,-1.101Zm0.033,-0.137l-0.017,0.07l0.017,-0.07l0.019,-0.077l-0.019,0.077Zm0.433,-1.625c-0.037,0.129 -0.073,0.258 -0.109,0.387c0.036,-0.129 0.072,-0.258 0.109,-0.387Z\" style=\"fill:#41cd52;\"/>"
              "</svg>");
    svg.close();

    Q_EMIT updateStatus(QStringLiteral("Done!"));
    Q_EMIT finished();
}
