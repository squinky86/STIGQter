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

#include "assetview.h"
#include "common.h"
#include "cklcheck.h"
#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"
#include "stigqter.h"
#include "ui_assetview.h"
#include "workerckl.h"
#include "workercklexport.h"

#include <QFileDialog>
#include <QFont>
#include <QInputDialog>
#include <QMessageBox>
#include <QShortcut>
#include <QXmlStreamWriter>
#include <QTimer>

#include <iostream>
#include <utility>

/**
 * @class AssetView
 * @brief The STIGViewer-like display of an Asset's STIG, checks, and
 * compliance status.
 *
 * The AssetView is the main STIG compliance view for a singular
 * Asset. It enumerates the applicable checks, their compliance
 * status, and provides commentary fields for each of the checks.
 *
 * The AssetView is a tabbed page, created dynamically, and closeable
 * by the user.
 */

/**
 * @brief AssetView::AssetView
 * @param asset
 * @param parent
 *
 * Main constructor.
 */
AssetView::AssetView(Asset &asset, QWidget *parent) :
    TabViewWidget(parent),
    ui(new Ui::AssetView),
    _asset(std::move(asset)),
    _justification(),
    _updateStatus(false),
    _isFiltered(false)
{
    ui->setupUi(this);

    //set splitter stretch factors
    ui->splitter->setStretchFactor(0, 1);
    ui->splitter->setStretchFactor(1, 3);
    ui->splitter->setStretchFactor(2, 2);

    /*
     * The main timer signals that the checklist entries have been
     * modified by the user. Since the user may be modifying large
     * portions of text, it is inefficient to update the database for
     * every user keystroke. Instead, the database of checklist
     * information is only updated if the user has been idle for a
     * little while. Delays are defined in UpdateCKL().
     */
    _timer.setSingleShot(true);
    connect(&_timer, SIGNAL(timeout()), this, SLOT(UpdateCKLHelper()));

    /*
     * CKLCheck counts are updated as defined in UpdateCKLHelper()
     */
    _timerChecks.setSingleShot(true);
    connect(&_timerChecks, SIGNAL(timeout()), this, SLOT(CountChecks()));

    /*
     * Shortcuts for quickly setting compliance state of selected
     * check(s):
     * 1. CTRL+N: Not a Finding
     * 2. CTRL+O: Open Finding
     * 3. CTRL+R: Not Reviewed
     * 4. CTRL+X: Not Applicable
     */
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_N), this, SLOT(KeyShortcutCtrlN())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_O), this, SLOT(KeyShortcutCtrlO())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_R), this, SLOT(KeyShortcutCtrlR())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_X), this, SLOT(KeyShortcutCtrlX())));

    if (_asset.id >= 0)
        Display();
}

/**
 * @brief AssetView::~AssetView
 *
 * Destructor.
 */
AssetView::~AssetView()
{
    Q_FOREACH (QShortcut *shortcut, _shortcuts)
        delete shortcut;
    _shortcuts.clear();
    delete ui;
}

/**
 * @brief STIGQter::DisableInput
 *
 * Prevent user interaction while background processes are busy.
 */
void AssetView::DisableInput()
{
    ui->txtIP->setEnabled(false);
    ui->txtMAC->setEnabled(false);
    ui->txtFQDN->setEnabled(false);
    ui->txtMarking->setEnabled(false);
    ui->txtSTIGFilter->setEnabled(false);
    ui->lstSTIGs->setEnabled(false);
    ui->cboBoxFilterStatus->setEnabled(false);
    ui->cboBoxFilterSeverity->setEnabled(false);
    ui->lstChecks->setEnabled(false);
    ui->btnDeleteAsset->setEnabled(false);
    ui->btnRename->setEnabled(false);
    ui->cboBoxSeverity->setEnabled(false);
    ui->toolBox->setEnabled(false);
    ui->cboBoxStatus->setEnabled(false);
    ui->txtFindingDetails->setEnabled(false);
    ui->txtComments->setEnabled(false);
    ui->btnImportXCCDF->setEnabled(false);
    ui->btnSaveCKL->setEnabled(false);
    ui->btnSaveCKLs->setEnabled(false);
    ui->btnUpgradeCKL->setEnabled(false);
}

/**
 * @brief AssetView::Display
 *
 * Shows the STIGs and CKL Checks for the selected Asset
 */
void AssetView::Display()
{
    ui->txtIP->setText(_asset.hostIP);
    ui->txtMAC->setText(_asset.hostMAC);
    ui->txtFQDN->setText(_asset.hostFQDN);
    ui->txtMarking->setText(_asset.marking);
    SelectSTIGs();
    ShowChecks();
}

/**
 * @brief AssetView::EnableInput
 *
 * Enable all controls when background worker finishes.
 */
void AssetView::EnableInput()
{
    ui->txtIP->setEnabled(true);
    ui->txtMAC->setEnabled(true);
    ui->txtFQDN->setEnabled(true);
    ui->txtMarking->setEnabled(true);
    ui->txtSTIGFilter->setEnabled(true);
    ui->lstSTIGs->setEnabled(true);
    ui->cboBoxFilterStatus->setEnabled(true);
    ui->cboBoxFilterSeverity->setEnabled(true);
    ui->lstChecks->setEnabled(true);
    ui->btnDeleteAsset->setEnabled(true);
    ui->btnRename->setEnabled(true);
    ui->cboBoxSeverity->setEnabled(true);
    ui->toolBox->setEnabled(true);
    ui->cboBoxStatus->setEnabled(true);
    ui->txtFindingDetails->setEnabled(true);
    ui->txtComments->setEnabled(true);
    ui->btnImportXCCDF->setEnabled(true);
    ui->btnSaveCKL->setEnabled(true);
    ui->btnSaveCKLs->setEnabled(true);
}

/**
 * @brief AssetView::GetTabType
 * @return TabType of Asset
 */
TabType AssetView::GetTabType()
{
    return TabType::asset;
}

/**
 * @brief AssetView::SelectSTIGs
 * @param search
 *
 * Marks the STIGs that are tied to the Asset as selected in the
 * list of all possible STIGs.
 */
void AssetView::SelectSTIGs(const QString &search)
{
    DbManager db;

    ui->lstSTIGs->clear();
    QVector<STIG> stigs = _asset.GetSTIGs();
    Q_FOREACH (const STIG s, db.GetSTIGs())
    {
        if (!search.isEmpty() && !s.title.contains(search, Qt::CaseInsensitive))
        {
            continue;
        }
        QListWidgetItem *i = new QListWidgetItem(PrintSTIG(s));
        ui->lstSTIGs->addItem(i);
        i->setData(Qt::UserRole, QVariant::fromValue<STIG>(s));
        i->setSelected(stigs.contains(s));
    }
}

/**
 * @brief AssetView::CountChecks
 *
 * Display/update the count of checks and their compliance statuses.
 */
void AssetView::CountChecks()
{
    ShowChecks(true);
}

/**
 * @brief AssetView::ShowChecks
 * @param countOnly
 *
 * When @a countOnly is @c true, the number of checks and their
 * compliance statuses are updated. When @a countOnly is @c false,
 * the display of CKL Checks is also updated.
 */
void AssetView::ShowChecks(bool countOnly)
{
    if (!countOnly)
        ui->lstChecks->clear();
    int total = 0; //total checks
    int open = 0; //findings
    int closed = 0; //passed checks

    QString filterSeverityText = ui->cboBoxFilterSeverity->currentText();
    Severity filterSeverity = GetSeverity(ui->cboBoxFilterSeverity->currentText());
    QString filterStatusText = ui->cboBoxFilterStatus->currentText();
    Status filterStatus = GetStatus(ui->cboBoxFilterStatus->currentText());

    Q_FOREACH(const CKLCheck c, _asset.GetCKLChecks())
    {
        total++;
        switch (c.status)
        {
        case Status::NotAFinding:
            closed++;
            break;
        case Status::Open:
            open++;
            break;
        default:
            break;
        }
        //update the list of CKL checks
        if (
                !countOnly //perform filtering
                && //severity filter
                ((filterSeverityText == QStringLiteral("All")) ||
                 (filterSeverity == c.GetSeverity()))
                && //status filter
                ((filterStatusText == QStringLiteral("All")) ||
                 (filterStatus == c.status))
            )
        {
            QListWidgetItem *i = new QListWidgetItem(PrintCKLCheck(c));
            ui->lstChecks->addItem(i);
            i->setData(Qt::UserRole, QVariant::fromValue<CKLCheck>(c));
            SetItemColor(i, c.status, (c.severityOverride == Severity::none) ? c.GetSTIGCheck().severity : c.severityOverride);
        }
    }
    ui->lblTotalChecks->setText(QString::number(total));
    ui->lblOpen->setText(QString::number(open));
    ui->lblNotAFinding->setText(QString::number(closed));
    if (!countOnly)
        ui->lstChecks->sortItems();
}

/**
 * @brief AssetView::UpdateCKLCheck
 * @param cklCheck
 *
 * Updates the displayed information about the selected CKL check,
 * @a cc, with information from the database.
 */
void AssetView::UpdateCKLCheck(const CKLCheck &cklCheck)
{
    //write database elemnets to user interface

    //While reading ui elements, disable their ability to throw an event.
    ui->txtComments->blockSignals(true);
    ui->txtFindingDetails->blockSignals(true);
    ui->cboBoxStatus->blockSignals(true);
    ui->cboBoxSeverity->blockSignals(true);

    //write @a cc information to the user interface
    ui->cboBoxStatus->setCurrentText(GetStatus(cklCheck.status));
    ui->txtComments->clear();
    ui->txtComments->insertPlainText(cklCheck.comments);
    ui->txtFindingDetails->clear();
    ui->txtFindingDetails->insertPlainText(cklCheck.findingDetails);
    _justification = cklCheck.severityJustification;

    //see if the check has a category-level override
    UpdateSTIGCheck(cklCheck.GetSTIGCheck());
    if (cklCheck.severityOverride != Severity::none)
        ui->cboBoxSeverity->setCurrentText(GetSeverity(cklCheck.severityOverride));

    //Now that the elements are updated from the DB, they can throw events again.
    ui->txtComments->blockSignals(false);
    ui->txtFindingDetails->blockSignals(false);
    ui->cboBoxStatus->blockSignals(false);
    ui->cboBoxSeverity->blockSignals(false);
}

/**
 * @brief AssetView::UpdateSTIGCheck
 * @param stigCheck
 *
 * Fill in user-interface information with the provided STIG.
 */
void AssetView::UpdateSTIGCheck(const STIGCheck &stigCheck)
{
    ui->lblCheckRule->setText(stigCheck.rule + QStringLiteral(" (") + (stigCheck.legacyIds.isEmpty() ? stigCheck.vulnNum : stigCheck.legacyIds.join(QStringLiteral(", "))) + QStringLiteral(")"));
    ui->lblCheckTitle->setText(stigCheck.title);
    ui->cboBoxSeverity->setCurrentText(GetSeverity(stigCheck.severity));
    ui->cbDocumentable->setChecked(stigCheck.documentable);
    ui->lblDiscussion->setText(stigCheck.vulnDiscussion);
    ui->lblFalsePositives->setText(stigCheck.falsePositives);
    ui->lblFalseNegatives->setText(stigCheck.falseNegatives);
    ui->lblFix->setText(stigCheck.fix);
    ui->lblCheck->setText(stigCheck.check);
    QString ccis(QStringLiteral("Relevant CCI(s):\n"));
    Q_FOREACH (auto cci, stigCheck.GetCCIs())
    {
        ccis.append(PrintCCI(cci) + QStringLiteral(": ") + cci.definition + QStringLiteral("\n"));
    }
    ui->lblCcis->setText(ccis);
}

#ifdef USE_TESTS
void AssetView::RunTests()
{
    int onTest = 0;
    //step 1: search for Windows components
    std::cout << "\t\tTest " << onTest++ << ": Filter" << std::endl;
    ui->txtSTIGFilter->setText(QStringLiteral("Windows"));

    //step 2: clear search
    std::cout << "\t\tTest " << onTest++ << ": Clear Filter" << std::endl;
    ui->txtSTIGFilter->setText(QString());

    //step 3: view all CKL checks
    std::cout << "\t\tTest " << onTest++ << ": View CKLs" << std::endl;
    {
        DbManager db;
        Q_FOREACH (const CKLCheck &cklCheck, db.GetCKLChecks())
        {
            UpdateCKLCheck(cklCheck);
        }
    }

    //step 4: when selected check changes
    std::cout << "\t\tTest " << onTest++ << ": Change Check Selection" << std::endl;
    ui->lstChecks->selectAll();

    //step 5: change findings
    std::cout << "\t\tTest " << onTest++ << ": Change Findings Status…";
    std::cout << "Not a Finding";
    KeyShortcutCtrlN();
    std::cout << "…";
    ProcEvents();
    std::cout << "Open";
    KeyShortcutCtrlO();
    std::cout << "…";
    ProcEvents();
    std::cout << "Not Reviewed";
    KeyShortcutCtrlR();
    std::cout << "…";
    ProcEvents();
    std::cout << "Not Applicable";
    KeyShortcutCtrlX();
    std::cout << "…";
    ProcEvents();
    std::cout << "done!" << std::endl;

    //step 6: update asset
    std::cout << "\t\tTest " << onTest++ << ": Change Asset" << std::endl;
    ui->txtFQDN->setText(QStringLiteral("test.example.org"));
    ui->txtIP->setText(QStringLiteral("127.0.0.1"));
    ui->txtMAC->setText(QStringLiteral("00:00:00:00:00:00"));
    ui->txtMarking->setText(QStringLiteral("PUBLIC RELEASE"));

    //step 7: save CKL
    std::cout << "\t\tSaving Monolithic CKL" << std::endl;
    SaveCKL(QStringLiteral("tests/monolithic.ckl"));
    ProcEvents();

    //step 8: save CKLs
    std::cout << "\t\tSaving Individual CKLs" << std::endl;
    SaveCKLs(QStringLiteral("tests/"));
    ProcEvents();

    //step 9: Count Checks
    std::cout << "\t\tTest " << onTest++ << ": Counting Checks" << std::endl;
    UpdateChecks();

    //step 10: import XCCDF
    std::cout << "\t\tTest " << onTest++ << ": Importing XCCDF" << std::endl;
    ImportXCCDF(QStringLiteral("tests/xccdf_lol.xml"));
    ProcEvents();

    //step 11: rename asset
    std::cout << "\t\tTest " << onTest++ << ": Rename Asset" << std::endl;
    RenameAsset("TEST2");
    RenameAsset("TEST");

    //step 12: delete asset
    std::cout << "\t\tTest " << onTest++ << ":Deleting Asset" << std::endl;
    DeleteAsset(true);
}
#endif

/**
 * @brief AssetView::CheckSelectedChanged
 *
 * Disables the ability to set finding details for multiple CKL
 * Checks at a time.
 */
void AssetView::CheckSelectedChanged()
{
    if (ui->lstChecks->selectedItems().count() > 1)
    {
        //disable multi-editable fields
        ui->txtComments->setEnabled(false);
        ui->txtFindingDetails->setEnabled(false);
        ui->cboBoxSeverity->setEnabled(false);
    }
    else
    {
        //enable multi-editable fields
        ui->txtComments->setEnabled(true);
        ui->txtFindingDetails->setEnabled(true);
        ui->cboBoxSeverity->setEnabled(true);
    }
}

/**
 * @brief AssetView::DeleteAsset
 *
 * Deletes this Asset from the database.
 */
void AssetView::DeleteAsset(bool confirm)
{
    //prompt user for confirmation of a destructive task
    QMessageBox::StandardButton reply = confirm ? QMessageBox::Yes : QMessageBox::question(this, QStringLiteral("Confirm"), "Are you sure you want to delete " + PrintAsset(_asset) + "?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes)
    {
        DbManager db;
        //remove all associated STIGs from this asset.
        Q_FOREACH (const STIG &s, _asset.GetSTIGs())
            db.DeleteSTIGFromAsset(s, _asset);
        db.DeleteAsset(_asset);
        if (_tabIndex > 0)
            Q_EMIT CloseTab(_tabIndex);
    }
}

/**
 * @brief STIGQter::FilterSTIGs
 * @param text
 *
 * Filter the STIG list based on search text
 */
void AssetView::FilterSTIGs(const QString &text)
{
    ui->lstSTIGs->blockSignals(true);
    if (text.length() > 2)
    {
        _isFiltered = true;
        SelectSTIGs(text);
    }
    else if (_isFiltered)
    {
        _isFiltered = false;
        SelectSTIGs();
    }
    ui->lstSTIGs->blockSignals(false);
}

/**
 * @brief AssetView::ImportXCCDF
 *
 * Import XCCDF file into this @a Asset.
 */
void AssetView::ImportXCCDF(const QString &filename)
{
    DbManager db;
    db.DelayCommit(true);

    QStringList fileNames;

    if (filename.isEmpty())
    {
        fileNames = QFileDialog::getOpenFileNames(this,
            QStringLiteral("Open XCCDF"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("XCCDF (*.xml)"));
    }
    else
    {
        fileNames.append(filename);
    }

    bool updates = false;

    //Allow multiple XCCDF files to be selected
    Q_FOREACH (const QString fileName, fileNames)
    {
        QFile f(fileName);
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
        if (!f.open(QFile::ReadOnly | QFile::Text))
        {
            QMessageBox::warning(nullptr, QStringLiteral("Unable to Open XCCDF"), "The XCCDF file " + fileName + " cannot be opened.");
            continue;
        }
        QXmlStreamReader *xml = new QXmlStreamReader(f.readAll());
        QStringView onCheck;
        QStringList warnings;
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement())
            {
                if (xml->name() == QStringLiteral("fact"))
                {
                    /*
                     * iterate through elements that can fill out .ckl checklist
                     * Elements include:
                     * ipv4
                     * mac
                     * fqdn
                     * We already have the Asset named, so don't overwrite it.
                     */
                    if (xml->attributes().hasAttribute(QStringLiteral("name")))
                    {
                        QStringView name = xml->attributes().value(QStringLiteral("name"));
                        if (name.endsWith(QStringLiteral("ipv4"), Qt::CaseInsensitive))
                        {
                            QString tmpStr = xml->readElementText();
                            if (!tmpStr.isNull() && !tmpStr.isEmpty())
                            {
                                ui->txtIP->setText(tmpStr);
                            }
                        }
                        else if (name.endsWith(QStringLiteral("mac"), Qt::CaseInsensitive))
                        {
                            QString tmpStr = xml->readElementText();
                            if (!tmpStr.isNull() && !tmpStr.isEmpty())
                            {
                                ui->txtMAC->setText(tmpStr);
                            }
                        }
                        else if (name.endsWith(QStringLiteral("fqdn"), Qt::CaseInsensitive))
                        {
                            QString tmpStr = xml->readElementText();
                            if (!tmpStr.isNull() && !tmpStr.isEmpty())
                            {
                                ui->txtFQDN->setText(tmpStr);
                            }
                        }
                    }
                }
                //Iterate through each rule and pull the status
                else if (xml->name() == QStringLiteral("rule-result"))
                {
                    if (xml->attributes().hasAttribute(QStringLiteral("idref")))
                    {
                        onCheck = xml->attributes().value(QStringLiteral("idref"));
                    }
                }
                else if (xml->name().compare(QStringLiteral("result")) == 0)
                {
                    if (!onCheck.startsWith(QStringLiteral("SV")) && onCheck.toString().contains(QStringLiteral("SV"))) //trim off XCCDF perfunctory information for benchmark files
                    {
                        onCheck = onCheck.right(onCheck.length() - onCheck.toString().indexOf(QStringLiteral("SV")));
                    }
                    CKLCheck ckl = db.GetCKLCheckByDISAId(_asset.id, onCheck.toString());
                    if (ckl.id < 0)
                    {
                        warnings.push_back(onCheck.toString());
                    }
                    else
                    {
                        QString result = xml->readElementText();
                        bool update = false;
                        if (result.startsWith(QStringLiteral("pass"), Qt::CaseInsensitive))
                        {
                            update = true;
                            ckl.status = Status::NotAFinding;
                        }
                        else if (result.startsWith(QStringLiteral("notapplicable"), Qt::CaseInsensitive))
                        {
                            update = true;
                            ckl.status = Status::NotApplicable;
                        }
                        else if (result.startsWith(QStringLiteral("fail"), Qt::CaseInsensitive))
                        {
                            update = true;
                            ckl.status = Status::Open;
                        }
                        if (update)
                        {
                            updates = true;
                            QFileInfo fi(f);
                            ckl.findingDetails += "This finding information was set by XCCDF file " + fi.fileName();
                            db.UpdateCKLCheck(ckl);
                        }
                    }
                }
            }
        }
        delete xml;
        auto tmpCount = warnings.count();
        //save a warning if the result can't be mapped to a check
        if (tmpCount > 0)
        {
            Warning(QStringLiteral("Unable to Find Check") + Pluralize(tmpCount), QStringLiteral("The CKLCheck") + Pluralize(tmpCount) + QStringLiteral(" ") + warnings.join(QStringLiteral(", ")) + QStringLiteral(" w") + Pluralize(tmpCount, QStringLiteral("ere"), QStringLiteral("as")) + QStringLiteral(" not found in this STIG."));
        }
    }
    db.DelayCommit(false);
    if (updates) //only update the checks if something changed
        ShowChecks();
}

void AssetView::KeyShortcutCtrlN()
{
    KeyShortcut(Status::NotAFinding);
}

void AssetView::KeyShortcutCtrlO()
{
    KeyShortcut(Status::Open);
}

void AssetView::KeyShortcutCtrlR()
{
    KeyShortcut(Status::NotReviewed);
}

void AssetView::KeyShortcutCtrlX()
{
    KeyShortcut(Status::NotApplicable);
}

/**
 * @brief AssetView::RenameAsset
 * @param name
 *
 * Prompts the user, requesting the new name for the asset.
 */
void AssetView::RenameAsset(const QString &name)
{
    bool ok = true;
    QString assetName = name.isEmpty() ? QInputDialog::getText(this, QStringLiteral("Input New Asset Name"), QStringLiteral("Asset Name"), QLineEdit::Normal, _asset.hostName, &ok) : name;
    DbManager db;
    if (db.GetAsset(assetName).id > 0)
    {
        Warning(QStringLiteral("Unable to Update Asset"), "Unable to change Asset name. " + assetName + " already exists in the database.");
    }
    else if (ok)
    {
        _asset.hostName = assetName;
        db.UpdateAsset(_asset);
        if (_tabIndex > 0)
            Q_EMIT RenameTab(_tabIndex, assetName);
    }
}

/**
 * @brief AssetView::SaveCKL
 *
 * Save the selected Asset as a single CKL file.
 */
void AssetView::SaveCKL(const QString &name)
{
    DbManager db;
    QString fileName = !name.isEmpty() ? name : QFileDialog::getSaveFileName(this, QStringLiteral("Save STIG/SRG Checklist"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIG Checklist (*.ckl)"));

    auto *a = new WorkerCKL();
    a->AddAsset(_asset);
    a->AddFilename(fileName);
    _parent->ConnectThreads(a)->start();
}

/**
 * @brief AssetView::SaveCKLs
 *
 * Save the selected Asset as multiple CKL files.
 */
void AssetView::SaveCKLs(const QString &dir)
{
    DbManager db;
    QString dirName = !dir.isEmpty() ? dir : QFileDialog::getExistingDirectory(this, QStringLiteral("Save to Directory"), db.GetVariable(QStringLiteral("lastdir")));

    if (!dirName.isNull() && !dirName.isEmpty())
    {
        DisableInput();
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(dirName).absolutePath());
        auto *f = new WorkerCKLExport();
        f->SetExportDir(dirName);
        f->SetAssetName(_asset.hostName);

        _parent->ConnectThreads(f)->start();
    }
}

/**
 * @brief AssetView::UpdateChecks
 *
 * Triggered when filters are updated, this will filter out the
 * checks that are not selected.
 */
void AssetView::UpdateChecks()
{
    ShowChecks();
}

/**
 * @brief AssetView::KeyShortcut
 * @param action
 *
 * When a keyboard shortcut is used, set the display element to
 * correspond.
 */
void AssetView::KeyShortcut(Status action)
{
    if (this->isVisible())
    {
        switch (action)
        {
        case Status::NotReviewed:
            ui->cboBoxStatus->setCurrentIndex(0);
            break;
        case Status::Open:
            ui->cboBoxStatus->setCurrentIndex(1);
            break;
        case Status::NotAFinding:
            ui->cboBoxStatus->setCurrentIndex(2);
            break;
        default:
            ui->cboBoxStatus->setCurrentIndex(3);
            break;
        }
    }
}

/**
 * @brief AssetView::UpdateCKLHelper
 *
 * Update the database with user-modified data from the interface.
 */
void AssetView::UpdateCKLHelper()
{
    QList<QListWidgetItem*> selectedItems = ui->lstChecks->selectedItems();
    int count = selectedItems.count();
    ui->btnUpgradeCKL->setEnabled(false);
    //make sure that something is selected
    if (count > 0)
    {
        DbManager db;
        db.DelayCommit(true);
        Q_FOREACH (QListWidgetItem *i, selectedItems)
        {
            auto cc = i->data(Qt::UserRole).value<CKLCheck>();
            //if multiple checks are selected, only update their status
            if (count < 2)
            {
                cc.comments = ui->txtComments->toPlainText();
                cc.findingDetails = ui->txtFindingDetails->toPlainText();
                Severity tmpSeverity = GetSeverity(ui->cboBoxSeverity->currentText());
                cc.severityOverride = (tmpSeverity == cc.GetSTIGCheck().severity) ? Severity::none : tmpSeverity;
                cc.severityJustification = _justification;
                cc.status = GetStatus(ui->cboBoxStatus->currentText());

                //check if STIG is upgradable
                STIG selectedSTIG = cc.GetSTIGCheck().GetSTIG();
                Q_FOREACH (STIG s, db.GetSTIGs())
                {
                    if (s != selectedSTIG)
                    {
                        if (
                                (s.title == selectedSTIG.title) &&
                                (
                                    (s.version > selectedSTIG.version) ||
                                    ((s.version == selectedSTIG.version) && (s.release.compare(selectedSTIG.release) > 0))
                                ) &&
                                (!_asset.GetSTIGs().contains(s))
                            )
                        {
                            ui->btnUpgradeCKL->setEnabled(true);
                            break;
                        }
                    }
                }
            }
            else {
                if (_updateStatus)
                {
                    cc.status = GetStatus(ui->cboBoxStatus->currentText());
                }
            }
            db.UpdateCKLCheck(cc);
            i->setData(Qt::UserRole, QVariant::fromValue<CKLCheck>(db.GetCKLCheck(cc)));
        }
        db.DelayCommit(false);
        _updateStatus = false;

        _timerChecks.start(1000);
    }
    //check if Asset was updated
    if ((_asset.hostIP != ui->txtIP->text()) || (_asset.hostMAC != ui->txtMAC->text()) || (_asset.hostFQDN != ui->txtFQDN->text()) || (_asset.marking != ui->txtMarking->text()))
    {
        DbManager db;
        _asset.hostIP = ui->txtIP->text();
        _asset.hostMAC = ui->txtMAC->text();
        _asset.hostFQDN = ui->txtFQDN->text();
        _asset.marking = ui->txtMarking->text();
        db.UpdateAsset(_asset);
    }
}

/**
 * @brief AssetView::UpdateCKL
 *
 * Detects when the user has made a change and been idle for a while.
 */
void AssetView::UpdateCKL()
{
    //avoid updating the database for every keypress. Wait for 9/50 of a second before saving
    //https://forum.qt.io/topic/97857/qplaintextedit-autosave-to-database
    _timer.start(180);
}

/**
 * @brief AssetView::UpdateCKLStatus
 * @param val
 * Trigger updating the visual elements for when the CKL status
 * changes its compliance state.
 */
void AssetView::UpdateCKLStatus(const QString &val)
{
    QList<QListWidgetItem*> selectedItems = ui->lstChecks->selectedItems();
    Status stat;
    stat = GetStatus(val);
    if (!selectedItems.isEmpty())
    {
        Q_FOREACH (QListWidgetItem *i, selectedItems)
        {
            auto cc = i->data(Qt::UserRole).value<CKLCheck>();
            STIGCheck sc = cc.GetSTIGCheck();
            SetItemColor(i, stat, (cc.severityOverride == Severity::none) ? sc.severity : cc.severityOverride);
        }
        _updateStatus = true;
        UpdateCKL();
    }
}

/**
 * @brief AssetView::UpdateCKLSeverity
 * @param val
 *
 * Handle changing the CKL check's severity when the CKL check's
 * severity has been overwritten.
 */
void AssetView::UpdateCKLSeverity(const QString &val)
{
    QList<QListWidgetItem*> selectedItems = ui->lstChecks->selectedItems();
    //should only be executed if one severity is set
    if (!selectedItems.isEmpty())
    {
        QListWidgetItem *i = selectedItems.first();
        auto cc = i->data(Qt::UserRole).value<CKLCheck>();
        STIGCheck sc = cc.GetSTIGCheck();
        Severity tmpSeverity = GetSeverity(val);
        if (sc.severity != tmpSeverity)
        {
            if (tmpSeverity == Severity::none)
            {
                QMessageBox::warning(nullptr, QStringLiteral("Removed Severity Override"), QStringLiteral("Severity override is removed; findings cannot be downgraded to CAT IV."));
                _justification = QString();
                ui->cboBoxSeverity->blockSignals(true);
                ui->cboBoxSeverity->setCurrentText(GetSeverity(sc.severity));
                ui->cboBoxSeverity->blockSignals(false);
            }
            else
            {
                bool ok(false);
                QString justification = QInputDialog::getMultiLineText(this, tr("Severity Override Justification"),
                                        tr("Justification:"), _justification, &ok);
                if (ok)
                {
                    _justification = justification;
                }
                else
                {
                    ui->cboBoxSeverity->blockSignals(true);
                    ui->cboBoxSeverity->setCurrentText(GetSeverity(sc.severity));
                    ui->cboBoxSeverity->blockSignals(false);
                    return;
                }
            }
        }
        SetItemColor(i, GetStatus(ui->cboBoxStatus->currentText()), GetSeverity(ui->cboBoxSeverity->currentText()));
        UpdateCKL();
    }
}

/**
 * @brief AssetView::UpdateSTIGs
 *
 * Handle the selection of which STIGs are included with the viewed
 * Asset;
 */
void AssetView::UpdateSTIGs()
{
    DbManager db;
    QVector<STIG> stigs = _asset.GetSTIGs();
    for (int i = 0; i < ui->lstSTIGs->count(); i++)
    {
        QListWidgetItem *item = ui->lstSTIGs->item(i);
        STIG s = item->data(Qt::UserRole).value<STIG>();
        if (item->isSelected() && !stigs.contains(s))
        {
            db.AddSTIGToAsset(s, _asset);
            ShowChecks();
        }
        else if (!item->isSelected() && stigs.contains(s))
        {
            //confirm to delete the STIG (avoid accidental clicks in the STIG box)
            QMessageBox::StandardButton confirm = QMessageBox::question(this, QStringLiteral("Confirm STIG Removal"), "Really delete the " + PrintSTIG(s) + " stig from " + PrintAsset(_asset) + "?",
                                            QMessageBox::Yes|QMessageBox::No);
            if (confirm == QMessageBox::Yes)
            {
                db.DeleteSTIGFromAsset(s, _asset);
                ShowChecks();
            }
            else
            {
                //keep STIG selected on accidental click
                ui->lstSTIGs->blockSignals(true);
                item->setSelected(true);
                ui->lstSTIGs->blockSignals(false);
            }
        }
    }
}

/**
 * @brief AssetView::UpgradeCKL
 *
 * Upgrades the selected STIG to a newer version
 */
void AssetView::UpgradeCKL()
{
    QListWidgetItem *i = ui->lstChecks->selectedItems().first();
    DbManager db;
    db.DelayCommit(true);
    auto cc = i->data(Qt::UserRole).value<CKLCheck>();
    //check if STIG is upgradable
    STIG selectedSTIG = cc.GetSTIGCheck().GetSTIG();
    Q_FOREACH (STIG s, db.GetSTIGs())
    {
        if (s != selectedSTIG)
        {
            if (
                    (s.title == selectedSTIG.title) &&
                    (
                        (s.version > selectedSTIG.version) ||
                        ((s.version == selectedSTIG.version) && (s.release.compare(selectedSTIG.release) > 0))
                    ) &&
                    (!_asset.GetSTIGs().contains(s))
                )
            {
                //found STIG to upgrade to
                db.AddSTIGToAsset(s, _asset);
                db.DelayCommit(true);
                Q_FOREACH (CKLCheck ckl, _asset.GetCKLChecks(&s))
                {
                    bool updated = false;
                    Q_FOREACH(CKLCheck ckl_old, _asset.GetCKLChecks(&selectedSTIG))
                    {
                        if (ckl_old.GetSTIGCheck().vulnNum == ckl.GetSTIGCheck().vulnNum)
                        {
                            ckl.status = ckl_old.status;
                            ckl.findingDetails = ckl_old.findingDetails;
                            ckl.comments = ckl_old.comments;
                            ckl.severityOverride = ckl_old.severityOverride;
                            ckl.severityJustification = ckl_old.severityJustification;
                            db.UpdateCKLCheck(ckl);
                            updated = true;
                            break;
                        }
                    }
                    if (updated)
                        continue;
                }
                db.DelayCommit(false);
                break;
            }
        }
    }
    QMessageBox::information(nullptr, QStringLiteral("STIG Added"), QStringLiteral("The upgraded STIG has been added to the asset."));
    ShowChecks();
}

/**
 * @brief AssetView::SetItemColor
 * @param i
 * @param stat
 * @param sev
 *
 * Sets the QListWidgetItem's color so that attention is drawn to it,
 * particularly when the check is non-compliant.
 */
void AssetView::SetItemColor(QListWidgetItem *i, Status stat, Severity sev)
{
    QFont f;
    i->setFont(f);
    if (stat == Status::Open)
    {
        f.setBold(true);
        i->setFont(f);
        switch (sev)
        {
        case Severity::high:
            i->setForeground(Qt::red);
            break;
        case Severity::medium:
            i->setForeground(QColor("orange"));
            break;
        case Severity::low:
            i->setForeground(Qt::yellow);
            break;
        default:
            i->setForeground(Qt::black);
            break;
        }
    }
    else if (stat == Status::NotAFinding)
    {
        i->setForeground(Qt::green);
    }
    else if (stat == Status::NotApplicable)
    {
        i->setForeground(Qt::gray);
    }
    else
    {
        i->setForeground(Qt::black);
    }
}

/**
 * @brief AssetView::CheckSelected
 *
 * When a new CKL check is selected, make sure that the previously displayed
 * one has updated its elements correctly.
 */
void AssetView::CheckSelected(QListWidgetItem *current, QListWidgetItem *previous [[maybe_unused]])
{
    if (current)
    {
        auto cc = current->data(Qt::UserRole).value<CKLCheck>();
        DbManager db;
        UpdateCKLCheck(db.GetCKLCheck(cc));
    }
}
