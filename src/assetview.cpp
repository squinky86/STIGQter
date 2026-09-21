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

#include "assetview.h"
#include "common.h"
#include "cklcheck.h"
#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"
#include "stigqter.h"
#include "ui_assetview.h"
#include "workerckl.h"
#include "workercklb.h"
#include "workercklexport.h"
#include "workercklupgrade.h"

#include <QFileDialog>
#include <QFont>
#include <QInputDialog>
#include <QMessageBox>
#include <QSettings>
#include <QSet>
#include <QShortcut>
#include <QSignalBlocker>
#include <QStyle>
#include <QXmlStreamWriter>
#include <QTimer>

#include <algorithm>
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

    //theme-consistent icons on the action buttons (purely cosmetic cues)
    QStyle *st = style();
    ui->btnDeleteAsset->setIcon(st->standardIcon(QStyle::SP_TrashIcon));
    ui->btnRename->setIcon(st->standardIcon(QStyle::SP_FileDialogDetailedView));
    ui->btnImportXCCDF->setIcon(st->standardIcon(QStyle::SP_DialogOpenButton));
    ui->btnSaveCKL->setIcon(st->standardIcon(QStyle::SP_DialogSaveButton));
    ui->btnSaveCKLs->setIcon(st->standardIcon(QStyle::SP_DialogSaveButton));
    ui->btnUpgradeCKL->setIcon(st->standardIcon(QStyle::SP_ArrowUp));
    ui->btnNextNotReviewed->setIcon(st->standardIcon(QStyle::SP_ArrowForward));

    ui->cboBoxFilterStatus->setItemData(1, static_cast<int>(Status::NotReviewed));
    ui->cboBoxFilterStatus->setItemData(2, static_cast<int>(Status::Open));
    ui->cboBoxFilterStatus->setItemData(3, static_cast<int>(Status::NotApplicable));
    ui->cboBoxFilterStatus->setItemData(4, static_cast<int>(Status::NotAFinding));
    ui->cboBoxFilterSeverity->setItemData(1, static_cast<int>(Severity::high));
    ui->cboBoxFilterSeverity->setItemData(2, static_cast<int>(Severity::medium));
    ui->cboBoxFilterSeverity->setItemData(3, static_cast<int>(Severity::low));
    ui->cboBoxFilterSeverity->setItemData(4, static_cast<int>(Severity::none));
    ui->cboBoxStatus->setToolTip(QStringLiteral(
        "Compliance status of the selected check(s).\n"
        "Shortcuts: Ctrl+R Not Reviewed, Ctrl+O Open, Ctrl+N Not a Finding, Ctrl+X Not Applicable."));
    ui->cboBoxSeverity->setToolTip(QStringLiteral("Severity override for the selected check (requires a justification)."));
    ui->txtFindingDetails->setToolTip(QStringLiteral("Finding details recorded for this check (exported to CKL and reports)."));
    ui->txtComments->setToolTip(QStringLiteral("Reviewer comments recorded for this check (exported to CKL and reports)."));
    ui->txtSTIGFilter->setPlaceholderText(QStringLiteral("Filter STIGs by title…"));
    ui->lblSaveState->setStyleSheet(QStringLiteral("QLabel { color: #007A33; }"));

    //subtle zebra striping for the longer scanning lists
    ui->lstChecks->setAlternatingRowColors(true);
    ui->lstChecks->setUniformItemSizes(true);
    ui->lstChecks->setTextElideMode(Qt::ElideRight);
    ui->lstSTIGs->setAlternatingRowColors(true);

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
    connect(ui->txtCheckSearch, &QLineEdit::textChanged, this, &AssetView::UpdateChecks);
    connect(ui->btnNextNotReviewed, &QPushButton::clicked, this, &AssetView::NextNotReviewed);

    {
        QSettings settings(QSettings::NativeFormat, QSettings::UserScope,
                           QStringLiteral("STIGQter"), QStringLiteral("STIGQter"));
        const QByteArray splitterState = settings.value(QStringLiteral("assessment/splitterState")).toByteArray();
        if (!splitterState.isEmpty())
            ui->splitter->restoreState(splitterState);
        const QSignalBlocker statusGuard(ui->cboBoxFilterStatus);
        const QSignalBlocker severityGuard(ui->cboBoxFilterSeverity);
        ui->cboBoxFilterStatus->setCurrentIndex(settings.value(QStringLiteral("assessment/statusFilter"), 0).toInt());
        ui->cboBoxFilterSeverity->setCurrentIndex(settings.value(QStringLiteral("assessment/severityFilter"), 0).toInt());
    }

    /*
     * Shortcuts for quickly setting compliance state of selected
     * check(s):
     * 1. CTRL+N: Not a Finding
     * 2. CTRL+O: Open Finding
     * 3. CTRL+R: Not Reviewed
     * 4. CTRL+X: Not Applicable
     */
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_N), this, SLOT(KeyShortcutCtrlN())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_O), this, SLOT(KeyShortcutCtrlO())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_R), this, SLOT(KeyShortcutCtrlR())));
    _shortcuts.append(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_X), this, SLOT(KeyShortcutCtrlX())));

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
    FlushPendingChanges();
    QSettings settings(QSettings::NativeFormat, QSettings::UserScope,
                       QStringLiteral("STIGQter"), QStringLiteral("STIGQter"));
    settings.setValue(QStringLiteral("assessment/splitterState"), ui->splitter->saveState());
    settings.setValue(QStringLiteral("assessment/statusFilter"), ui->cboBoxFilterStatus->currentIndex());
    settings.setValue(QStringLiteral("assessment/severityFilter"), ui->cboBoxFilterSeverity->currentIndex());
    for (QShortcut *shortcut : _shortcuts)
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
    ui->txtCheckSearch->setEnabled(false);
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
    ui->btnNextNotReviewed->setEnabled(false);
}

/**
 * @brief AssetView::Display
 *
 * Shows the STIGs and CKL Checks for the selected Asset
 */
void AssetView::Display()
{
    ui->btnUpgradeCKL->setEnabled(false);
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
    ui->txtCheckSearch->setEnabled(true);
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
    ui->btnNextNotReviewed->setEnabled(ui->lblNotReviewed->text().toInt() > 0);
    CheckSelectedChanged();
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
    const QSignalBlocker selectionGuard(ui->lstSTIGs);

    ui->lstSTIGs->clear();
    QVector<STIG> stigs = _asset.GetSTIGs();
    for (const STIG &s : db.GetSTIGs())
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
    const bool filtersActive = !ui->txtCheckSearch->text().trimmed().isEmpty()
        || ui->cboBoxFilterStatus->currentIndex() != 0
        || ui->cboBoxFilterSeverity->currentIndex() != 0;
    ShowChecks(!filtersActive);
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
    const bool signalsWereBlocked = ui->lstChecks->signalsBlocked();
    const bool updatesWereEnabled = ui->lstChecks->updatesEnabled();
    QSet<int> selectedIds;
    int currentId = -1;
    if (!countOnly)
    {
        for (QListWidgetItem *item : ui->lstChecks->selectedItems())
            selectedIds.insert(item->data(Qt::UserRole).value<CKLCheck>().id);
        if (ui->lstChecks->currentItem())
            currentId = ui->lstChecks->currentItem()->data(Qt::UserRole).value<CKLCheck>().id;
        ui->lstChecks->blockSignals(true);
        ui->lstChecks->setUpdatesEnabled(false);
        ui->lstChecks->clear();
    }
    int total = 0;
    int open = 0;
    int notAFinding = 0;
    int notReviewed = 0;
    int notApplicable = 0;
    int shown = countOnly ? ui->lstChecks->count() : 0;

    const bool filterSeverity = ui->cboBoxFilterSeverity->currentIndex() != 0;
    const Severity selectedSeverity = static_cast<Severity>(ui->cboBoxFilterSeverity->currentData().toInt());
    const bool filterStatus = ui->cboBoxFilterStatus->currentIndex() != 0;
    const Status selectedStatus = static_cast<Status>(ui->cboBoxFilterStatus->currentData().toInt());
    const QString search = ui->txtCheckSearch->text().trimmed();
    QListWidgetItem *restoredCurrent = nullptr;

    QVector<CKLCheck> checks = _asset.GetCKLChecks();
    if (!countOnly)
    {
        std::sort(checks.begin(), checks.end(), [](const CKLCheck &left, const CKLCheck &right) {
            return left.GetRule().compare(right.GetRule(), Qt::CaseInsensitive) < 0;
        });
    }

    for (const CKLCheck &c : checks)
    {
        total++;
        switch (c.status)
        {
        case Status::NotAFinding:
            notAFinding++;
            break;
        case Status::Open:
            open++;
            break;
        case Status::NotApplicable:
            notApplicable++;
            break;
        case Status::NotReviewed:
            notReviewed++;
            break;
        default:
            break;
        }

        const QString searchable = QStringList({c.GetRule(), c.GetVulnerabilityId(), c.GetTitle(), c.GetSTIGTitle()})
                                       .join(QLatin1Char('\n'));
        const bool matches = (!filterSeverity || selectedSeverity == c.GetSeverity())
            && (!filterStatus || selectedStatus == c.status)
            && (search.isEmpty() || searchable.contains(search, Qt::CaseInsensitive));
        if (!countOnly && matches)
        {
            auto *i = new QListWidgetItem();
            ui->lstChecks->addItem(i);
            UpdateCheckItem(i, c);
            ++shown;
            if (selectedIds.contains(c.id))
                i->setSelected(true);
            if (c.id == currentId)
                restoredCurrent = i;
        }
    }
    ui->lblTotalChecks->setText(QString::number(total));
    ui->lblOpen->setText(QString::number(open));
    ui->lblOpen->setStyleSheet(open > 0
        ? QStringLiteral("QLabel { color: #C8102E; font-weight: bold; }")
        : QStringLiteral("QLabel { color: #6B7280; }"));
    ui->lblNotAFinding->setText(QString::number(notAFinding));
    ui->lblNotAFinding->setStyleSheet(notAFinding > 0
        ? QStringLiteral("QLabel { color: #007A33; font-weight: bold; }")
        : QStringLiteral("QLabel { color: #6B7280; }"));
    ui->lblNotReviewed->setText(QString::number(notReviewed));
    ui->lblNotApplicable->setText(QString::number(notApplicable));
    const int reviewed = total - notReviewed;
    const int percentReviewed = total > 0 ? (reviewed * 100) / total : 0;
    ui->lblReviewed->setText(QStringLiteral("Reviewed: %1/%2 (%3%)")
                                 .arg(reviewed).arg(total).arg(percentReviewed));
    ui->lblFilteredChecks->setText(QStringLiteral("Showing %1 of %2 checks").arg(shown).arg(total));
    ui->btnNextNotReviewed->setEnabled(ui->lstChecks->isEnabled() && notReviewed > 0);
    if (!countOnly)
    {
        if (restoredCurrent)
            ui->lstChecks->setCurrentItem(restoredCurrent);
        ui->lstChecks->setUpdatesEnabled(updatesWereEnabled);
        ui->lstChecks->blockSignals(signalsWereBlocked);
        if (!signalsWereBlocked)
        {
            CheckSelected(ui->lstChecks->currentItem(), nullptr);
            CheckSelectedChanged();
        }
    }
}

void AssetView::UpdateCheckItem(QListWidgetItem *item, const CKLCheck &check)
{
    if (!item)
        return;

    const QString status = GetStatus(check.status);
    const QString severity = GetSeverity(check.GetSeverity());
    item->setText(QStringLiteral("%1  ·  %2  ·  %3 — %4")
                      .arg(check.GetRule(), status, severity, check.GetTitle()));
    item->setToolTip(QStringLiteral("%1\n%2\n%3 — %4\n%5")
                         .arg(check.GetSTIGTitle(), check.GetRule(), check.GetVulnerabilityId(),
                              check.GetTitle(), status + QStringLiteral(" · ") + severity));
    item->setData(Qt::AccessibleTextRole, item->text());
    item->setData(Qt::AccessibleDescriptionRole, item->toolTip());
    item->setData(Qt::UserRole, QVariant::fromValue<CKLCheck>(check));
    SetItemColor(item, check.status, check.GetSeverity());
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
    DbManager db;

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

    //check if STIG is upgradable
    STIG selectedSTIG = cklCheck.GetSTIGCheck().GetSTIG();
    for (STIG s : db.GetSTIGs())
    {
        if (s != selectedSTIG)
        {
            if (
                    (s.title == selectedSTIG.title) &&
                    (
                        s.IsNewerThan(selectedSTIG)
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
    ui->lblDiscussion->setPlainText(stigCheck.vulnDiscussion);
    ui->lblFalsePositives->setPlainText(stigCheck.falsePositives);
    ui->lblFalseNegatives->setPlainText(stigCheck.falseNegatives);
    ui->lblFix->setPlainText(stigCheck.fix);
    ui->lblCheck->setPlainText(stigCheck.check);
    const auto displayValue = [](const QString &value) {
        return value.trimmed().isEmpty() ? QStringLiteral("Not provided") : value;
    };
    QStringList additionalDetails;
    additionalDetails
        << QStringLiteral("Vulnerability ID: ") + displayValue(stigCheck.vulnNum)
        << QStringLiteral("Group title: ") + displayValue(stigCheck.groupTitle)
        << QStringLiteral("Rule version: ") + displayValue(stigCheck.ruleVersion)
        << QStringLiteral("Weight: ") + QString::number(stigCheck.weight)
        << QStringLiteral("Mitigations: ") + displayValue(stigCheck.mitigations)
        << QStringLiteral("Severity override guidance: ") + displayValue(stigCheck.severityOverrideGuidance)
        << QStringLiteral("Check content reference: ") + displayValue(stigCheck.checkContentRef)
        << QStringLiteral("Potential impact: ") + displayValue(stigCheck.potentialImpact)
        << QStringLiteral("Third-party tools: ") + displayValue(stigCheck.thirdPartyTools)
        << QStringLiteral("Mitigation control: ") + displayValue(stigCheck.mitigationControl)
        << QStringLiteral("Responsibility: ") + displayValue(stigCheck.responsibility)
        << QStringLiteral("IA controls: ") + displayValue(stigCheck.iaControls)
        << QStringLiteral("Target key: ") + displayValue(stigCheck.targetKey);
    ui->lblAdditionalDetails->setPlainText(additionalDetails.join(QStringLiteral("\n\n")));
    QString ccis(QStringLiteral("Relevant CCI(s):\n"));
    for (auto cci : stigCheck.GetCCIs())
    {
        ccis.append(PrintCCI(cci) + QStringLiteral(": ") + cci.definition + QStringLiteral("\n"));
    }
    ui->lblCcis->setPlainText(ccis);
}

void AssetView::RunTests()
{
    int onTest = 0;
    qDebug("AssetView test %d: Filter", onTest++);
    ui->txtSTIGFilter->setText(QStringLiteral("Windows"));

    qDebug("AssetView test %d: Clear Filter", onTest++);
    ui->txtSTIGFilter->setText(QString());

    qDebug("AssetView test %d: View CKLs", onTest++);
    {
        DbManager db;
        for (const CKLCheck &cklCheck : db.GetCKLChecks())
        {
            UpdateCKLCheck(cklCheck);
        }
    }

    qDebug("AssetView test %d: Change Check Selection", onTest++);
    ui->lstChecks->selectAll();

    qDebug("AssetView test %d: Change Findings Status", onTest++);
    KeyShortcutCtrlN();
    ProcEvents();
    KeyShortcutCtrlO();
    ProcEvents();
    KeyShortcutCtrlR();
    ProcEvents();
    KeyShortcutCtrlX();
    ProcEvents();

    qDebug("AssetView test %d: Change Asset", onTest++);
    ui->txtFQDN->setText(QStringLiteral("test.example.org"));
    ui->txtIP->setText(QStringLiteral("127.0.0.1"));
    ui->txtMAC->setText(QStringLiteral("00:00:00:00:00:00"));
    ui->txtMarking->setText(QStringLiteral("PUBLIC RELEASE"));

    qDebug("AssetView test %d: Save Monolithic CKL", onTest++);
    SaveCKL(QStringLiteral("tests/monolithic.ckl"));
    ProcEvents();

    qDebug("AssetView test %d: Save Individual CKLs", onTest++);
    SaveCKLs(QStringLiteral("tests/"));
    ProcEvents();

    qDebug("AssetView test %d: Count Checks", onTest++);
    UpdateChecks();

    qDebug("AssetView test %d: Import XCCDF", onTest++);
    ImportXCCDF(QStringLiteral("tests/xccdf_lol.xml"));
    ProcEvents();

    qDebug("AssetView test %d: Rename Asset", onTest++);
    RenameAsset(QStringLiteral("TEST2"));
    RenameAsset(QStringLiteral("TEST"));

    qDebug("AssetView test %d: Upgrade ASD STIG", onTest++);
    ui->lstChecks->clearSelection();
    ProcEvents();
    for (int j = 0; j < ui->lstChecks->count(); j++)
    {
        CKLCheck cc = ui->lstChecks->item(j)->data(Qt::UserRole).value<CKLCheck>();
        if (cc.GetSTIGCheck().GetSTIG().fileName.compare(QStringLiteral("U_ASD_STIG_V5R1_Manual-xccdf.xml")) == 0)
        {
            ui->lstChecks->item(j)->setSelected(true);
            ProcEvents();
            break;
        }
    }
    UpgradeCKL();
    ProcEvents();

    qDebug("AssetView test %d: Delete Asset", onTest++);
    DeleteAsset(true);
}

/**
 * @brief AssetView::CheckSelectedChanged
 *
 * Disables the ability to set finding details for multiple CKL
 * Checks at a time.
 */
void AssetView::CheckSelectedChanged()
{
    const int selectedCount = ui->lstChecks->selectedItems().count();
    const bool inputEnabled = ui->lstChecks->isEnabled();
    const bool hasSingleSelection = inputEnabled && selectedCount == 1;

    ui->txtComments->setEnabled(hasSingleSelection);
    ui->txtFindingDetails->setEnabled(hasSingleSelection);
    ui->cboBoxSeverity->setEnabled(hasSingleSelection);
    ui->cboBoxStatus->setEnabled(inputEnabled && selectedCount > 0);
}

/**
 * @brief AssetView::DeleteAsset
 *
 * Deletes this Asset from the database.
 */
void AssetView::DeleteAsset(bool confirm)
{
    FlushPendingChanges();
    //prompt user for confirmation of a destructive task
    QMessageBox::StandardButton reply = confirm ? QMessageBox::Yes : QMessageBox::question(this, QStringLiteral("Confirm"), "Are you sure you want to delete " + PrintAsset(_asset) + "?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes)
    {
        DbManager db;
        //remove all associated STIGs from this asset.
        for (const STIG &s : _asset.GetSTIGs())
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
    if (!text.isEmpty())
    {
        _isFiltered = true;
        SelectSTIGs(text);
    }
    else if (_isFiltered)
    {
        _isFiltered = false;
        SelectSTIGs();
    }
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
    for (const QString &fileName : fileNames)
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

void AssetView::NextNotReviewed()
{
    int currentId = -1;
    if (ui->lstChecks->currentItem())
        currentId = ui->lstChecks->currentItem()->data(Qt::UserRole).value<CKLCheck>().id;

    {
        const QSignalBlocker searchGuard(ui->txtCheckSearch);
        const QSignalBlocker statusGuard(ui->cboBoxFilterStatus);
        const QSignalBlocker severityGuard(ui->cboBoxFilterSeverity);
        ui->txtCheckSearch->clear();
        ui->cboBoxFilterStatus->setCurrentIndex(0);
        ui->cboBoxFilterSeverity->setCurrentIndex(0);
    }
    ShowChecks();

    int startRow = -1;
    for (int row = 0; row < ui->lstChecks->count(); ++row)
    {
        if (ui->lstChecks->item(row)->data(Qt::UserRole).value<CKLCheck>().id == currentId)
        {
            startRow = row;
            break;
        }
    }
    for (int offset = 1; offset <= ui->lstChecks->count(); ++offset)
    {
        const int row = (startRow + offset) % ui->lstChecks->count();
        QListWidgetItem *item = ui->lstChecks->item(row);
        if (item->data(Qt::UserRole).value<CKLCheck>().status == Status::NotReviewed)
        {
            ui->lstChecks->setCurrentItem(item, QItemSelectionModel::ClearAndSelect);
            ui->lstChecks->scrollToItem(item, QAbstractItemView::PositionAtCenter);
            break;
        }
    }
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
    FlushPendingChanges();
    DbManager db;
    QString fileName = name;
    if (fileName.isEmpty())
    {
        fileName = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("Save STIG/SRG Checklist"),
            db.GetVariable(QStringLiteral("lastdir")),
            QStringLiteral("STIG Checklist (*.ckl);;STIG Viewer 3 Checklist (*.cklb)"));
    }

    if (fileName.isEmpty())
        return;

    if (fileName.endsWith(QStringLiteral(".cklb"), Qt::CaseInsensitive))
    {
        auto *a = new WorkerCKLB();
        a->AddAsset(_asset);
        a->AddFilename(fileName);
        _parent->ConnectThreads(a)->start();
    }
    else
    {
        auto *a = new WorkerCKL();
        a->AddAsset(_asset);
        a->AddFilename(fileName);
        _parent->ConnectThreads(a)->start();
    }
}

/**
 * @brief AssetView::SaveCKLs
 *
 * Save the selected Asset as multiple CKL files.
 */
void AssetView::SaveCKLs(const QString &dir)
{
    FlushPendingChanges();
    DbManager db;

    // When called from tests a dir is pre-supplied; otherwise ask the user for
    // both the output directory and the desired file format.
    bool cklb = false;
    if (dir.isEmpty())
    {
        QMessageBox fmt;
        fmt.setWindowTitle(QStringLiteral("Choose export format"));
        fmt.setText(QStringLiteral("Select the checklist format to export:"));
        fmt.addButton(QStringLiteral("CKL (STIG Viewer 2)"),  QMessageBox::AcceptRole);
        QPushButton *btnCKLB = fmt.addButton(QStringLiteral("CKLB (STIG Viewer 3)"), QMessageBox::AcceptRole);
        fmt.addButton(QMessageBox::Cancel);
        fmt.exec();
        if (fmt.clickedButton() == nullptr || fmt.clickedButton() == fmt.button(QMessageBox::Cancel))
            return;
        cklb = (fmt.clickedButton() == btnCKLB);
    }

    QString dirName = !dir.isEmpty() ? dir : QFileDialog::getExistingDirectory(this, QStringLiteral("Save to Directory"), db.GetVariable(QStringLiteral("lastdir")));

    if (!dirName.isNull() && !dirName.isEmpty())
    {
        DisableInput();
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(dirName).absolutePath());
        auto *f = new WorkerCKLExport();
        f->SetExportDir(dirName);
        f->SetAssetName(_asset.hostName);
        f->SetCKLB(cklb);

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
    FlushPendingChanges();
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
    bool saveSucceeded = true;
    if (!_pendingChecks.isEmpty())
    {
        DbManager db;
        db.DelayCommit(true);
        const QMap<int, CKLCheck> pendingChecks = _pendingChecks;
        for (const CKLCheck &cc : pendingChecks)
        {
            saveSucceeded = db.UpdateCKLCheck(cc) && saveSucceeded;
            const CKLCheck savedCheck = db.GetCKLCheck(cc);
            for (int row = 0; row < ui->lstChecks->count(); ++row)
            {
                QListWidgetItem *item = ui->lstChecks->item(row);
                if (item->data(Qt::UserRole).value<CKLCheck>().id == cc.id)
                {
                    UpdateCheckItem(item, savedCheck);
                    break;
                }
            }
        }
        db.DelayCommit(false);
        _pendingChecks.clear();

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
        saveSucceeded = db.UpdateAsset(_asset) && saveSucceeded;
        //the system marking auto-escalates to the highest asset marking
        if (_parent)
            _parent->RefreshClassificationBanner();
    }
    ui->lblSaveState->setText(saveSucceeded ? QStringLiteral("All changes saved")
                                            : QStringLiteral("Unable to save changes"));
    ui->lblSaveState->setStyleSheet(saveSucceeded
        ? QStringLiteral("QLabel { color: #007A33; }")
        : QStringLiteral("QLabel { color: #C8102E; font-weight: bold; }"));
}

/**
 * @brief AssetView::UpdateCKL
 *
 * Detects when the user has made a change and been idle for a while.
 */
void AssetView::UpdateCKL()
{
    const QList<QListWidgetItem*> selectedItems = ui->lstChecks->selectedItems();
    const int count = selectedItems.count();
    for (QListWidgetItem *item : selectedItems)
    {
        CKLCheck cc = item->data(Qt::UserRole).value<CKLCheck>();
        if (count == 1)
        {
            cc.comments = ui->txtComments->toPlainText();
            cc.findingDetails = ui->txtFindingDetails->toPlainText();
            const Severity severity = GetSeverity(ui->cboBoxSeverity->currentText());
            cc.severityOverride = (severity == cc.GetSTIGCheck().severity) ? Severity::none : severity;
            cc.severityJustification = _justification;
            cc.status = GetStatus(ui->cboBoxStatus->currentText());
        }
        else if (_updateStatus)
        {
            cc.status = GetStatus(ui->cboBoxStatus->currentText());
        }
        else
        {
            continue;
        }

        _pendingChecks.insert(cc.id, cc);
        UpdateCheckItem(item, cc);
    }
    _updateStatus = false;

    //avoid updating the database for every keypress. Wait for 9/50 of a second before saving
    //https://forum.qt.io/topic/97857/qplaintextedit-autosave-to-database
    ui->lblSaveState->setText(QStringLiteral("Saving…"));
    ui->lblSaveState->setStyleSheet(QStringLiteral("QLabel { color: #6B7280; }"));
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
        for (QListWidgetItem *i : selectedItems)
        {
            auto cc = i->data(Qt::UserRole).value<CKLCheck>();
            SetItemColor(i, stat, cc.GetSeverity());
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
        const Severity previousSeverity = cc.GetSeverity();
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
                QString prompt = tr("Justification:");
                if (!sc.severityOverrideGuidance.trimmed().isEmpty())
                    prompt += tr("\n\nSTIG guidance:\n") + sc.severityOverrideGuidance;
                QString justification = QInputDialog::getMultiLineText(this, tr("Severity Override Justification"),
                                        prompt, _justification, &ok);
                if (ok && !justification.trimmed().isEmpty())
                {
                    _justification = justification;
                }
                else
                {
                    if (ok)
                        Warning(QStringLiteral("Severity Override Requires Justification"),
                                QStringLiteral("Enter a justification before changing the severity."));
                    ui->cboBoxSeverity->blockSignals(true);
                    ui->cboBoxSeverity->setCurrentText(GetSeverity(previousSeverity));
                    ui->cboBoxSeverity->blockSignals(false);
                    return;
                }
            }
        }
        else
        {
            _justification.clear();
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
    FlushPendingChanges();
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
    FlushPendingChanges();
    DisableInput();
    QListWidgetItem *i = ui->lstChecks->selectedItems().first();
    DbManager db;
    db.DelayCommit(true);
    auto cc = i->data(Qt::UserRole).value<CKLCheck>();

    auto *a = new WorkerCKLUpgrade();
    a->AddSTIG(_asset, cc.GetSTIGCheck().GetSTIG());
    _parent->ConnectThreads(a)->start();
    Q_EMIT CloseTab(_tabIndex);
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
    //Accessible palette: these colors are chosen to stay legible on the
    //white check-list background (unlike bright yellow/green). Open findings
    //are bold and warm-colored by severity to draw the eye; compliant and
    //not-applicable checks recede.
    QFont f;
    i->setFont(f);
    if (stat == Status::Open)
    {
        f.setBold(true);
        i->setFont(f);
        switch (sev)
        {
        case Severity::high:
            i->setForeground(QColor(0xC8, 0x10, 0x2E)); //CAT I - deep red
            break;
        case Severity::medium:
            i->setForeground(QColor(0xC1, 0x67, 0x00)); //CAT II - dark orange
            break;
        case Severity::low:
            i->setForeground(QColor(0x8A, 0x6D, 0x00)); //CAT III - dark amber (legible on white)
            break;
        default:
            i->setForeground(QColor(0x1C, 0x1E, 0x21)); //informational/open - near-black
            break;
        }
    }
    else if (stat == Status::NotAFinding)
    {
        i->setForeground(QColor(0x00, 0x7A, 0x33)); //compliant - accessible green
    }
    else if (stat == Status::NotApplicable)
    {
        i->setForeground(QColor(0x6B, 0x72, 0x80)); //N/A - muted grey
    }
    else
    {
        i->setForeground(QColor(0x1C, 0x1E, 0x21)); //not reviewed - near-black
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
    ui->btnUpgradeCKL->setEnabled(false);
    if (current)
    {
        auto cc = current->data(Qt::UserRole).value<CKLCheck>();
        if (_pendingChecks.contains(cc.id))
        {
            UpdateCKLCheck(_pendingChecks.value(cc.id));
        }
        else
        {
            DbManager db;
            UpdateCKLCheck(db.GetCKLCheck(cc));
        }
    }
}

void AssetView::FlushPendingChanges()
{
    const bool needsFlush = _timer.isActive() || !_pendingChecks.isEmpty();
    if (_timer.isActive())
        _timer.stop();
    if (needsFlush)
        UpdateCKLHelper();
}
