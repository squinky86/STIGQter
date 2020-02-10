/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2020 Jon Hood, http://www.hoodsecurity.com/
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

#include "assetview.h"
#include "common.h"
#include "dbmanager.h"
#include "help.h"
#include "stigqter.h"
#include "workerassetadd.h"
#include "workercklexport.h"
#include "workercklimport.h"
#include "workercmrsexport.h"
#include "workeremassreport.h"
#include "workerfindingsreport.h"
#include "workerhtml.h"
#include "workerimportemass.h"
#include "workermapunmapped.h"
#include "workerstigadd.h"
#include "workerstigdelete.h"

#include <QApplication>
#include <QDirIterator>
#include <QTemporaryFile>
#include <QThread>
#include <cstdlib>
#include <iostream>

[[maybe_unused]] bool IgnoreWarnings = false; //see common.h

int main(int argc, char *argv[])
{
    qInstallMessageHandler(MessageHandler);
    QApplication a(argc, argv);

    STIGQter w;
    w.show();

#ifdef USE_TESTS
    bool tests = false;

    for (int i = 0; i < argc; i++)
    {
        if (std::string_view(argv[i]) == "tests")
            tests = true;
    }

    if (tests)
    {
        int onTest = 0;

        //general information
        {
            std::cout << "Running Tests in " << QDir::currentPath().toStdString() << std::endl;
        }

        //run tests
        IgnoreWarnings = true;

        {
            std::cout << "Test " << ++onTest << ": Reset the DB" << std::endl;
            DbManager db;
            db.DeleteDB();
        }

        {
            std::cout << "Test " << ++onTest << ": Increase Log Level" << std::endl;
            DbManager db;
            db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("99"));
        }

        std::cout << "Test " << ++onTest << ": Index CCIs" << std::endl;
        QMetaObject::invokeMethod(&w, "UpdateCCIs", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        std::cout << "Test " << ++onTest << ": Index STIGs" << std::endl;
        QMetaObject::invokeMethod(&w, "DownloadSTIGs", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Import eMASS Test Results" << std::endl;
            DbManager db;
            WorkerImportEMASS wi;
            wi.SetReportName("tests/eMASSTRImport.xlsx");
            wi.process();
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Severity Override" << std::endl;
            DbManager db;
            int count = 0;
            Q_FOREACH(auto cklCheck, db.GetCKLChecks())
            {
                count++;
                //override checks' severity pseudorandomly
                switch (count % 4)
                {
                case 0:
                    if (cklCheck.GetSeverity() == Severity::none)
                        continue;
                    cklCheck.severityOverride = Severity::none;
                    cklCheck.severityJustification = QStringLiteral("Overridden to none.");
                    break;
                case 1:
                    if (cklCheck.GetSeverity() == Severity::low)
                        continue;
                    cklCheck.severityOverride = Severity::low;
                    cklCheck.severityJustification = QStringLiteral("Overridden to low.");
                    break;
                case 2:
                    if (cklCheck.GetSeverity() == Severity::medium)
                        continue;
                    cklCheck.severityOverride = Severity::medium;
                    cklCheck.severityJustification = QStringLiteral("Overridden to medium.");
                    break;
                case 3:
                    if (cklCheck.GetSeverity() == Severity::high)
                        continue;
                    cklCheck.severityOverride = Severity::high;
                    cklCheck.severityJustification = QStringLiteral("Overridden to high.");
                    break;
                default:
                    continue;
                }
            }
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Decrease Log Level" << std::endl;
            DbManager db;
            db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("0"));
        }

        {
            std::cout << "Test " << ++onTest << ": Run STIGQter Interface Tests" << std::endl;
            w.RunTests();
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Delete an Asset" << std::endl;
            DbManager db;
            Q_FOREACH (auto asset, db.GetAssets())
            {
                //remove each STIG from this asset
                Q_FOREACH (auto stig, asset.GetSTIGs())
                {
                    db.DeleteSTIGFromAsset(stig, asset);
                    a.processEvents();
                }
                db.DeleteAsset(asset);
            }
            a.processEvents();
        }

        {
            QDirIterator it("tests");
            WorkerCKLImport wc;
            while (it.hasNext())
            {
                QFile f(it.next());
                if (f.fileName().endsWith(".ckl", Qt::CaseInsensitive))
                {
                    //skip monolithic CKL
                    if (f.fileName().endsWith("monolithic.ckl", Qt::CaseInsensitive))
                        continue;
                    std::cout << "Test " << ++onTest << ": Import CKL " << f.fileName().toStdString() << std::endl;
                    QFileInfo fi(f);
                    wc.AddCKLs({fi.filePath()});
                }
            }
            wc.process();
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Delete eMASS Import" << std::endl;
            QMetaObject::invokeMethod(&w, "DeleteEmass", Qt::DirectConnection);
            while (!w.isProcessingEnabled())
            {
                QThread::sleep(1);
                a.processEvents();
            }
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Delete STIGs" << std::endl;
            WorkerSTIGDelete wd;
            DbManager db;
            Q_FOREACH (auto stig, db.GetSTIGs())
            {
                wd.AddId(stig.id);
            }
            wd.process();
            a.processEvents();
        }

        std::cout << "Test " << ++onTest << ": Delete CCIs" << std::endl;
        QMetaObject::invokeMethod(&w, "DeleteCCIs", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        //std::cout << "Test " << ++onTest << ": Close Application" << std::endl;
        //w.close();

        std::cout << "Tests complete!" << std::endl;
        exit(EXIT_SUCCESS);
    }
#endif

    return a.exec();
}
