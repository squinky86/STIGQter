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

#ifndef STIGQTER_H
#define STIGQTER_H

#include <QMainWindow>
#include <QSettings>

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
    QThread* ConnectThreads(Worker *worker, bool blocking = true);
    void Display();
    void RefreshClassificationBanner();
    void UpdateSTIGs();
    void ProcEvents();
    void RunTests();
    void RunTests1();
    void RunTests2();
    void RunTests3();
    void RunTests4();
    void RunTests5();

private Q_SLOTS:

    void CompletedThread();
    void CompletedThreadUnblocked();

    Help* About();
    void AddAsset(const QString &name = QString());
    void AddSTIGs();
    void CheckVersion();
    void CloseTab(int index);
    void DeleteAssets();
    void DeleteCCIs();
    void DeleteEmass();
    void DeleteSTIGs();
    void DownloadSTIGs();
    void EditSTIG();
    void ExportCKLs(const QString &dir = QString());
    void ExportCKLsMonolithic(const QString &dir = QString());
    void ExportCMRS(const QString &fileName = QString());
    void ExportEMASS(const QString &fileName = QString());
    void ExportHTML(const QString &dir = QString());
    void FilterSTIGs(const QString &text);
    void FindingsReport(const QString &fileName = QString());
    void ImportCKLs(const QStringList &fileNames = {});
    void ImportEMASS(const QString &fileName = QString());
    void ImportEmassControl(const QString &fileName = QString());
    void Load(const QString &fileName = QString());
    void MapUnmapped(bool confirm = false);
    void OpenCKL();
    void POAMTemplate(const QString &fileName = QString(), bool APNumLevel = true);
    void POAMTemplateControl(const QString &fileName = QString());
    void RemapChanged(int checkState);
    void RenameTab(int index, const QString &title);
    bool Reset(bool checkOnly = false);
    void Save();
    void SaveAs(const QString &fileName = QString());
    void SaveMarking();
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
    bool _busy;
    QString lastSaveLocation;
    void closeEvent(QCloseEvent *event);
    void CleanThreads();
    void DisableInput();
    void DisplayAssets();
    void DisplayCCIs();
    void DisplaySTIGs(const QString &search = QString());
    void EnableInput();
    void RefreshUiState();
    void SetButtonIcons();
    void UpdateProjectStatus();
    void UpdateRemapButton();
    bool _isFiltered;
    int _testStep = 0;
};

#endif // STIGQTER_H
