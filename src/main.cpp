/*
 * STIGQter - STIG fun with Qt
 *
 * Copyright © 2018–2022 Jon Hood, http://www.hoodsecurity.com/
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
#include "stigqter.h"

#include <QApplication>

#ifdef USE_TESTS
#include "assetview.h"
#include "dbmanager.h"
#include "stigqter.h"
#include "workerassetdelete.h"
#include "workercklimport.h"
#include "workerstigdelete.h"

#include <QDirIterator>
#include <QTemporaryFile>
#include <QThread>
#include <cstdlib>
#include <iostream>
#endif

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
            std::cout << "Test " << ++onTest << ": Increase Log Level & set supplements" << std::endl;
            DbManager db;
            db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("99"));
            db.UpdateVariable(QStringLiteral("indexSupplements"), QStringLiteral("y"));
        }

        std::cout << "Test " << ++onTest << ": Waiting for version check to complete." << std::endl;
        a.processEvents();
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        std::cout << "Test " << ++onTest << ": Index CCIs" << std::endl;
        QMetaObject::invokeMethod(&w, "UpdateCCIs", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Update a CCI" << std::endl;
            DbManager db;
            CCI cci = db.GetCCIByCCI(366);
            cci.definition.append(QStringLiteral(" (edited)"));
            db.UpdateCCI(cci);
            a.processEvents();
        }

        std::cout << "Test " << ++onTest << ": Include STIG Supplements" << std::endl;
        QMetaObject::invokeMethod(&w, "SupplementsChanged", Qt::DirectConnection, Q_ARG(int, Qt::Checked));
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
            std::cout << "Test " << ++onTest << ": Delete Asset" << std::endl;
            WorkerAssetDelete wd;
            DbManager db;
            QVector<Asset> toDelete = db.GetAssets();
            wd.AddAssets(toDelete);
            Q_FOREACH (auto asset, toDelete)
            {
                //remove each STIG from this asset
                Q_FOREACH (auto stig, asset.GetSTIGs())
                {
                    WorkerSTIGDelete wsd;
                    wsd.AddId(stig.id);
                    wsd.process();
                    a.processEvents();
                }
                //double-adding the asset should be gracefully handled without error
                wd.AddAsset(asset);
            }
            wd.process();
            a.processEvents();
        }

        {
            std::cout << "Test " << ++onTest << ": Hashing DB" << std::endl;
            DbManager db;
            auto hashInfo = db.HashDB();
            if (hashInfo.isNull() || hashInfo.isEmpty())
                std::cout << "Hashing failed." << std::endl;
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

        {
            QDirIterator it(QStringLiteral("tests"));
            WorkerCKLImport wc;
            while (it.hasNext())
            {
                QFile f(it.next());
                if (f.fileName().endsWith(QStringLiteral(".ckl"), Qt::CaseInsensitive))
                {
                    //skip monolithic CKL
                    if (f.fileName().endsWith(QStringLiteral("monolithic.ckl"), Qt::CaseInsensitive))
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

        std::cout << "Test " << ++onTest << ": Delete CCIs" << std::endl;
        QMetaObject::invokeMethod(&w, "DeleteCCIs", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        std::cout << "Test " << ++onTest << ": Delete All Assets" << std::endl;
        QMetaObject::invokeMethod(&w, "DeleteAssets", Qt::DirectConnection);
        while (!w.isProcessingEnabled())
        {
            QThread::sleep(1);
            a.processEvents();
        }

        std::cout << "Tests complete!" << std::endl;
        exit(EXIT_SUCCESS);
    }
#endif

    return a.exec();
}
