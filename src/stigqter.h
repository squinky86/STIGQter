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

#ifndef STIGQTER_H
#define STIGQTER_H

#include <QMainWindow>
#include <QSettings>
#include <QShortcut>

#include "dbmanager.h"
#include "help.h"
#include "worker.h"

namespace Ui {
    class STIGQter;
}

class STIGQter : public QMainWindow
{
    Q_OBJECT

public:
    explicit STIGQter(QWidget *parent = nullptr);
    ~STIGQter();
    bool isProcessingEnabled();
    QThread* ConnectThreads(Worker *worker);
    void UpdateSTIGs();
#ifdef USE_TESTS
    void ProcEvents();
    void RunTests();
#endif

private Q_SLOTS:

    void CompletedThread();

    Help* About();
    void AddAsset(const QString &name = QString());
    void AddSTIGs();
    void CloseTab(int index);
    void DeleteCCIs();
    void DeleteEmass();
    void DeleteSTIGs();
    void DownloadSTIGs();
    void EditSTIG();
    void ExportCKLs(const QString &dir = QString());
    void ExportCMRS(const QString &fileName = QString());
    void ExportEMASS(const QString &fileName = QString());
    void ExportHTML(const QString &dir = QString());
    void FilterSTIGs(const QString &text);
    void FindingsReport(const QString &fileName = QString());
    void ImportCKLs(const QStringList &fileNames = {});
    void ImportEMASS(const QString &fileName = QString());
    void Load(const QString &fileName = QString());
    void MapUnmapped(bool confirm = false);
    void OpenCKL();
    bool Reset(bool checkOnly = false);
    void Save();
    void SaveAs(const QString &fileName = QString());
    void SelectAsset();
    void SelectSTIG();
    void StatusChange(const QString &status);
    void ShowMessage(const QString &title, const QString &message);
    void SupplementsChanged(int checkState);
    void UpdateCCIs();

    void Initialize(int max, int val = 0);
    void Progress(int val);

private:
    Ui::STIGQter *ui;
    QList<QThread *> threads;
    QList<Worker *> workers;
    bool _updatedAssets;
    bool _updatedCCIs;
    bool _updatedSTIGs;
    QString lastSaveLocation;
    QList<QShortcut*> _shortcuts;
    void closeEvent(QCloseEvent *event);
    void CleanThreads();
    void DisableInput();
    void DisplayAssets();
    void DisplayCCIs();
    void DisplaySTIGs(const QString &search = QString());
    void EnableInput();
    bool _isFiltered;
};

#endif // STIGQTER_H
