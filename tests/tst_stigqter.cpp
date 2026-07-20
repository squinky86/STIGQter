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

void TestSTIGQter::test00_Classification()
{
    //parsing of free-text markings into ranked classification levels
    QCOMPARE(GetClassification(QStringLiteral("")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("PUBLIC RELEASE")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("UNCLASSIFIED")), Classification::classUnclassified);
    QCOMPARE(GetClassification(QStringLiteral("FOUO")), Classification::classFOUO);
    QCOMPARE(GetClassification(QStringLiteral("CUI [Controlled by: ...]")), Classification::classCUI);
    QCOMPARE(GetClassification(QStringLiteral("CONTROLLED")), Classification::classCUI);
    QCOMPARE(GetClassification(QStringLiteral("CONFIDENTIAL")), Classification::classConfidential);
    QCOMPARE(GetClassification(QStringLiteral("SECRET//NOFORN")), Classification::classSecret);
    QCOMPARE(GetClassification(QStringLiteral("TOP SECRET//SI")), Classification::classTopSecret);
    QCOMPARE(GetClassification(QStringLiteral("N/A")), Classification::classPublicRelease);

    //a complete classification word is required: markings that merely start with
    //the same letter (or embed the word in another word) must not escalate
    QCOMPARE(GetClassification(QStringLiteral("Storage array")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Firewall")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Unit 5")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Secretary workstation")), Classification::classPublicRelease);
    QCOMPARE(GetClassification(QStringLiteral("Controller node")), Classification::classPublicRelease);

    //ordering used for the import mismatch comparison
    QVERIFY(Classification::classTopSecret > Classification::classSecret);
    QVERIFY(Classification::classSecret > Classification::classCUI);
    QVERIFY(Classification::classCUI > Classification::classUnclassified);

    //canonical labels
    QCOMPARE(GetClassificationString(Classification::classCUI), QStringLiteral("CUI"));
    QCOMPARE(GetClassificationString(Classification::classSecret), QStringLiteral("SECRET"));
    QCOMPARE(GetClassificationString(Classification::classTopSecret), QStringLiteral("TOP SECRET"));
    QCOMPARE(GetClassificationString(Classification::classPublicRelease), QStringLiteral("PUBLIC RELEASE"));
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

// STIGQter::RunTests() is split into five phases so that each gets its own
// Qt Test per-function watchdog budget (default 300 s). Running the whole
// sequence as a single test function under the SonarCloud coverage build
// (-O0 with gcov instrumentation) exceeded that budget and aborted.
void TestSTIGQter::test04a_RunInterface()
{
    {
        DbManager db;
        db.UpdateVariable(QStringLiteral("loglevel"), QStringLiteral("0"));
    }

    w->RunTests1();
    procEvents();
    QVERIFY(w->isProcessingEnabled());

    //RunTests1 sets the system classification marking via the Main-tab field
    {
        DbManager db;
        QCOMPARE(db.GetVariable(QStringLiteral("systemMarking")), QStringLiteral("CUI"));
    }
}

void TestSTIGQter::test04b_RunInterface()
{
    w->RunTests2();
    procEvents();
    QVERIFY(w->isProcessingEnabled());

    //STIGEdit::RunTests() exports a STIG via WorkerSTIGExport; confirm the
    //archive was written and is a well-formed, re-importable XCCDF benchmark.
    QVERIFY(QFile::exists(QStringLiteral("tests/exported_stig.zip")));
    QMap<QString, QByteArray> exported = GetFilesFromZip(QStringLiteral("tests/exported_stig.zip"));
    bool foundXccdf = false;
    for (auto i = exported.constBegin(); i != exported.constEnd(); ++i)
    {
        if (i.key().endsWith(QStringLiteral("-xccdf.xml"), Qt::CaseInsensitive) ||
            i.key().endsWith(QStringLiteral("Manual_STIG.xml"), Qt::CaseInsensitive) ||
            i.key().endsWith(QStringLiteral("Manual_xccdf.xml"), Qt::CaseInsensitive))
        {
            foundXccdf = true;
            const QByteArray &xml = i.value();
            QVERIFY(xml.contains("<Benchmark"));
            QVERIFY(xml.contains("<Rule"));
        }
    }
    QVERIFY(foundXccdf);
}

void TestSTIGQter::test04c_RunInterface()
{
    w->RunTests3();
    procEvents();
    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::test04d_RunInterface()
{
    w->RunTests4();
    procEvents();
    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::test04e_RunInterface()
{
    w->RunTests5();
    procEvents();
    QVERIFY(w->isProcessingEnabled());
}

void TestSTIGQter::test04f_Escalation()
{
    DbManager db;
    QVector<Asset> assets = db.GetAssets();
    QVERIFY(!assets.isEmpty());

    //lower the system marking, then mark an asset higher than it
    db.UpdateVariable(QStringLiteral("systemMarking"), QStringLiteral("UNCLASSIFIED"));
    Asset a = assets.first();
    a.marking = QStringLiteral("SECRET");
    db.UpdateAsset(a);

    //the system marking auto-escalates to the highest asset marking
    w->RefreshClassificationBanner();
    procEvents();
    QCOMPARE(GetClassification(db.GetVariable(QStringLiteral("systemMarking"))), Classification::classSecret);
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
