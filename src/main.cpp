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

#include "assetview.h"
#include "common.h"
#include "dbmanager.h"
#include "stigqter.h"
#include "workerassetadd.h"
#include "workerstigadd.h"

#include <QApplication>
#include <QTemporaryFile>
#include <QThread>
#include <cstdlib>

[[maybe_unused]] bool IgnoreWarnings = false; //see common.h

int main(int argc, char *argv[])
{
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
        //run tests
        IgnoreWarnings = true;

        //test 0 - reset DB
        {
            DbManager db;
            db.DeleteDB();
        }

        //test 1 - index CCIs
        QMetaObject::invokeMethod(&w, "UpdateCCIs", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        //test 2 - add STIGs
        QTemporaryFile tmpFile;
        if (tmpFile.open())
        {
            QUrl stigs(QStringLiteral("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SRG-STIG_Library_2019_10v2.zip"));
            DownloadFile(stigs, &tmpFile);
            auto stigFiles = GetFilesFromZip(tmpFile.fileName().toStdString().c_str(), QStringLiteral(".zip")).values();
            Q_FOREACH (auto stigFile, stigFiles)
            {
                WorkerSTIGAdd tmpWorker;
                QTemporaryFile tmpFile2;
                if (tmpFile2.open())
                {
                    tmpFile2.write((stigFile));
                }
                tmpFile2.close();
                QStringList tmpList;
                tmpList.push_back(tmpFile2.fileName());
                tmpWorker.AddSTIGs(tmpList);
                tmpWorker.process();
                a.processEvents();
            }
            tmpFile.close();
            a.processEvents();
        }

        //test 3 - create Asset
        {
            DbManager db;
            WorkerAssetAdd wa;
            Asset tmpAsset;
            tmpAsset.hostName = QString("TEST");
            tmpAsset.hostIP = QString("127.0.0.1");
            tmpAsset.hostMAC = QString("00:00:00:00:00");
            tmpAsset.hostFQDN = QString("localhost");
            wa.AddAsset(tmpAsset);
            //map each STIG to this asset
            Q_FOREACH (auto stig, db.GetSTIGs())
            {
                wa.AddSTIG(stig);
            }
            wa.process();
            a.processEvents();
        }

        //test 4 - run STIGQter tests
        {
            w.RunTests();
            a.processEvents();
        }

        //test 5 - delete Asset
        {
            DbManager db;
            Q_FOREACH (auto asset, db.GetAssets())
            {
                //remove each STIG from this asset
                Q_FOREACH (auto stig, asset.GetSTIGs())
                {
                    db.DeleteSTIGFromAsset(stig, asset);
                }
                db.DeleteAsset(asset);
            }
            a.processEvents();
        }

        //test 6 - delete STIGs
        {
            DbManager db;
            Q_FOREACH (auto stig, db.GetSTIGs())
            {
                db.DeleteSTIG(stig);
                a.processEvents();
            }
            a.processEvents();
        }

        //test 7 - delete CCIs
        QMetaObject::invokeMethod(&w, "DeleteCCIs", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        w.close();
        exit(EXIT_SUCCESS);
    }
#endif

    return a.exec();
}
