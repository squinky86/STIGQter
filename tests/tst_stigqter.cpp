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

#include "tst_stigqter.h"

#include "common.h"
#include "dbmanager.h"
#include "stigqter.h"
#include "workerassetdelete.h"
#include "workercklimport.h"
#include "workerstigdelete.h"

#include <QDirIterator>
#include <QThread>
#include <QtTest>

TestSTIGQter::TestSTIGQter(QObject *parent) : QObject(parent)
{
}

void TestSTIGQter::procEvents()
{
    while (!w->isProcessingEnabled())
    {
        QThread::sleep(1);
        QApplication::processEvents();
    }
    QApplication::processEvents();
}

void TestSTIGQter::initTestCase()
{
    IgnoreWarnings = true;

    w = new STIGQter();
    w->show();

    {
        DbManager db;
        db.DeleteDB();
    }

    {
        DbManager db;
        db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("99"));
        db.UpdateVariable(QStringLiteral("indexSupplements"), QStringLiteral("y"));
    }

    QApplication::processEvents();
    procEvents();
}

void TestSTIGQter::test01_IndexCCIs()
{
    QMetaObject::invokeMethod(w, "UpdateCCIs", Qt::DirectConnection);
    procEvents();

    DbManager db;
    QVERIFY(db.GetCCIs().count() > 0);
}

void TestSTIGQter::test02_UpdateCCI()
{
    DbManager db;
    CCI cci = db.GetCCIByCCI(366);
    cci.definition.append(QStringLiteral(" (edited)"));
    db.UpdateCCI(cci);
    QApplication::processEvents();
}

void TestSTIGQter::test03_IndexSTIGs()
{
    QMetaObject::invokeMethod(w, "SupplementsChanged", Qt::DirectConnection, Q_ARG(int, Qt::Checked));
    procEvents();

    QMetaObject::invokeMethod(w, "DownloadSTIGs", Qt::DirectConnection);
    procEvents();

    DbManager db;
    QVERIFY(db.GetSTIGs().count() > 0);
}

void TestSTIGQter::test04_RunInterface()
{
    {
        DbManager db;
        db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("0"));
    }

    w->RunTests();
    QApplication::processEvents();
    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::test05_DeleteAndHash()
{
    {
        WorkerAssetDelete wd;
        DbManager db;
        QVector<Asset> toDelete = db.GetAssets();
        wd.AddAssets(toDelete);
        for (auto asset : toDelete)
        {
            for (auto stig : asset.GetSTIGs())
            {
                WorkerSTIGDelete wsd;
                wsd.AddId(stig.id);
                wsd.process();
                QApplication::processEvents();
            }
            wd.AddAsset(asset);
        }
        wd.process();
        QApplication::processEvents();
    }

    {
        DbManager db;
        auto hashInfo = db.HashDB();
        QVERIFY(!hashInfo.isNull() && !hashInfo.isEmpty());
        QApplication::processEvents();
    }

    {
        WorkerSTIGDelete wd;
        DbManager db;
        for (auto stig : db.GetSTIGs())
        {
            wd.AddId(stig.id);
        }
        wd.process();
        QApplication::processEvents();
    }
}

void TestSTIGQter::test06_CKLImport()
{
    QDirIterator it(QStringLiteral("tests"));
    WorkerCKLImport wc;
    while (it.hasNext())
    {
        QFile f(it.next());
        if (f.fileName().endsWith(QStringLiteral(".ckl"), Qt::CaseInsensitive))
        {
            if (f.fileName().endsWith(QStringLiteral("monolithic.ckl"), Qt::CaseInsensitive))
                continue;
            QFileInfo fi(f);
            wc.AddCKLs({fi.filePath()});
        }
    }
    wc.process();
    QApplication::processEvents();
}

void TestSTIGQter::test07_Cleanup()
{
    QMetaObject::invokeMethod(w, "DeleteEmass", Qt::DirectConnection);
    procEvents();

    QMetaObject::invokeMethod(w, "DeleteCCIs", Qt::DirectConnection);
    procEvents();

    QMetaObject::invokeMethod(w, "DeleteAssets", Qt::DirectConnection);
    procEvents();

    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::cleanupTestCase()
{
    w->close();
    delete w;
    w = nullptr;
}

QTEST_MAIN(TestSTIGQter)
