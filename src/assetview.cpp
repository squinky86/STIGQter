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
#include "cklcheck.h"
#include "dbmanager.h"
#include "stig.h"
#include "stigcheck.h"
#include "ui_assetview.h"

#include <QFileDialog>
#include <QFont>
#include <QInputDialog>
#include <QMessageBox>
#include <QShortcut>
#include <QXmlStreamWriter>
#include <QTimer>
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
AssetView::AssetView(const Asset &asset, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AssetView),
    _asset(std::move(asset)),
    _justification(),
    _updateStatus(false),
    _tabIndex(-1)
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
    foreach (QShortcut *shortcut, _shortcuts)
        delete shortcut;
    _shortcuts.clear();
    delete ui;
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
    SelectSTIGs();
    ShowChecks();
}

/**
 * @brief AssetView::SelectSTIGs
 *
 * Marks the STIGs that are tied to the Asset as selected in the
 * list of all possible STIGs.
 */
void AssetView::SelectSTIGs()
{
    DbManager db;
    //ui->lstSTIGs->blockSignals(true);
    ui->lstSTIGs->clear();
    QList<STIG> stigs = _asset.GetSTIGs();
    foreach (const STIG s, db.GetSTIGs())
    {
        QListWidgetItem *i = new QListWidgetItem(PrintSTIG(s));
        ui->lstSTIGs->addItem(i);
        i->setData(Qt::UserRole, QVariant::fromValue<STIG>(s));
        i->setSelected(stigs.contains(s));
    }
    //ui->lstSTIGs->blockSignals(false);
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

    foreach(const CKLCheck c, _asset.GetCKLChecks())
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
    ui->lblCheckRule->setText(stigCheck.rule);
    ui->lblCheckTitle->setText(stigCheck.title);
    ui->cboBoxSeverity->setCurrentText(GetSeverity(stigCheck.severity));
    ui->cbDocumentable->setChecked(stigCheck.documentable);
    ui->lblDiscussion->setText(stigCheck.vulnDiscussion);
    ui->lblFalsePositives->setText(stigCheck.falsePositives);
    ui->lblFalseNegatives->setText(stigCheck.falseNegatives);
    ui->lblFix->setText(stigCheck.fix);
    ui->lblCheck->setText(stigCheck.check);
}

/**
 * @brief AssetView::SetTabIndex
 * @param index
 *
 * Keep up with which index this tab is in the interface.
 */
void AssetView::SetTabIndex(int index)
{
    _tabIndex = index;
}

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
void AssetView::DeleteAsset()
{
    //prompt user for confirmation of a destructive task
    QMessageBox::StandardButton reply = QMessageBox::question(this, QStringLiteral("Confirm"), "Are you sure you want to delete " + PrintAsset(_asset) + "?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes)
    {
        DbManager db;
        //remove all associated STIGs from this asset.
        foreach (const STIG &s, _asset.GetSTIGs())
            db.DeleteSTIGFromAsset(s, _asset);
        db.DeleteAsset(_asset);
        if (_tabIndex > 0)
            emit CloseTab(_tabIndex);
    }
}

/**
 * @brief AssetView::ImportXCCDF
 *
 * Import XCCDF file into this @a Asset.
 */
void AssetView::ImportXCCDF()
{
    DbManager db;
    db.DelayCommit(true);

    QStringList fileNames = QFileDialog::getOpenFileNames(this,
        QStringLiteral("Open XCCDF"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("XCCDF (*.xml)"));

    bool updates = false;

    foreach (const QString fileName, fileNames)
    {
        QFile f(fileName);
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
        if (!f.open(QFile::ReadOnly | QFile::Text))
        {
            QMessageBox::warning(nullptr, QStringLiteral("Unable to Open XCCDF"), "The XCCDF file " + fileName + " cannot be opened.");
            continue;
        }
        QXmlStreamReader *xml = new QXmlStreamReader(f.readAll());
        QStringRef onCheck;
        QStringList warnings;
        while (!xml->atEnd() && !xml->hasError())
        {
            xml->readNext();
            if (xml->isStartElement())
            {
                if (xml->name() == QStringLiteral("fact"))
                {
                    if (xml->attributes().hasAttribute(QStringLiteral("name")))
                    {
                        QStringRef name = xml->attributes().value(QStringLiteral("name"));
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
                else if (xml->name() == QStringLiteral("rule-result"))
                {
                    if (xml->attributes().hasAttribute(QStringLiteral("idref")))
                    {
                        onCheck = xml->attributes().value(QStringLiteral("idref"));
                    }
                }
                else if (xml->name() == "result")
                {
                    if (!onCheck.startsWith(QStringLiteral("SV")) && onCheck.contains(QStringLiteral("SV"))) //trim off XCCDF perfunctory information for benchmark files
                    {
                        onCheck = onCheck.right(onCheck.length() - onCheck.indexOf(QStringLiteral("SV")));
                    }
                    CKLCheck ckl = db.GetCKLCheckByDISAId(_asset.id, onCheck.toString());
                    if (ckl.id < 0)
                    {
                        warnings.push_back(onCheck.toString());
                        //Warning(QStringLiteral("Unable to Find Check"), QStringLiteral("The CKLCheck '") + onCheck + QStringLiteral("' was not found in this STIG."));
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
        int tmpCount = warnings.count();
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
 *
 * Prompts the user, requesting the new name for the asset.
 */
void AssetView::RenameAsset()
{
    bool ok;
    QString assetName = QInputDialog::getText(this, QStringLiteral("Input New Asset Name"), QStringLiteral("Asset Name"), QLineEdit::Normal, _asset.hostName, &ok);
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
            emit CloseTab(_tabIndex);
    }
}

/**
 * @brief AssetView::SaveCKL
 *
 * Save the selected Asset as a single CKL file.
 */
void AssetView::SaveCKL()
{
    DbManager db;
    QString fileName = QFileDialog::getSaveFileName(this, QStringLiteral("Save STIG/SRG Checklist"), db.GetVariable(QStringLiteral("lastdir")), QStringLiteral("STIG Checklist (*.ckl)"));
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly))
    {
        db.UpdateVariable(QStringLiteral("lastdir"), QFileInfo(fileName).absolutePath());
        QXmlStreamWriter stream(&file);
        //xml for a CKL file
        stream.writeStartDocument(QStringLiteral("1.0"));
        stream.writeComment("STIGQter :: " + VERSION);
        stream.writeStartElement(QStringLiteral("CHECKLIST"));
        stream.writeStartElement(QStringLiteral("ASSET"));
        stream.writeStartElement(QStringLiteral("ROLE"));
        stream.writeCharacters(QStringLiteral("None"));
        stream.writeEndElement(); //ROLE
        stream.writeStartElement(QStringLiteral("ASSET_TYPE"));
        stream.writeCharacters(_asset.assetType);
        stream.writeEndElement(); //ASSET_TYPE
        stream.writeStartElement(QStringLiteral("HOST_NAME"));
        stream.writeCharacters(_asset.hostName);
        stream.writeEndElement(); //HOST_NAME
        stream.writeStartElement(QStringLiteral("HOST_IP"));
        stream.writeCharacters(_asset.hostIP);
        stream.writeEndElement(); //HOST_IP
        stream.writeStartElement(QStringLiteral("HOST_MAC"));
        stream.writeCharacters(_asset.hostMAC);
        stream.writeEndElement(); //HOST_MAC
        stream.writeStartElement(QStringLiteral("HOST_FQDN"));
        stream.writeCharacters(_asset.hostFQDN);
        stream.writeEndElement(); //HOST_FQDN
        stream.writeStartElement(QStringLiteral("TECH_AREA"));
        stream.writeCharacters(_asset.techArea);
        stream.writeEndElement(); //TECH_AREA
        stream.writeStartElement(QStringLiteral("TARGET_KEY"));
        stream.writeCharacters(_asset.targetKey);
        stream.writeEndElement(); //TARGET_KEY
        stream.writeStartElement(QStringLiteral("WEB_OR_DATABASE"));
        stream.writeCharacters(PrintTrueFalse(_asset.webOrDB));
        stream.writeEndElement(); //WEB_OR_DATABASE
        stream.writeStartElement(QStringLiteral("WEB_DB_SITE"));
        stream.writeCharacters(_asset.webDbSite);
        stream.writeEndElement(); //WEB_DB_SITE
        stream.writeStartElement(QStringLiteral("WEB_DB_INSTANCE"));
        stream.writeCharacters(_asset.webDbInstance);
        stream.writeEndElement(); //WEB_DB_INSTANCE
        stream.writeEndElement(); //ASSET
        stream.writeStartElement(QStringLiteral("STIGS"));
        foreach (const STIG &s, _asset.GetSTIGs())
        {
            stream.writeStartElement(QStringLiteral("iSTIG"));
            stream.writeStartElement(QStringLiteral("STIG_INFO"));

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            stream.writeStartElement(QStringLiteral("SID_NAME"));
            stream.writeCharacters(QStringLiteral("version"));
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement(QStringLiteral("SID_DATA"));
            stream.writeCharacters(QString::number(s.version));
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            stream.writeStartElement(QStringLiteral("SID_NAME"));
            stream.writeCharacters(QStringLiteral("stigid"));
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement(QStringLiteral("SID_DATA"));
            stream.writeCharacters(s.benchmarkId);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            stream.writeStartElement(QStringLiteral("SID_NAME"));
            stream.writeCharacters(QStringLiteral("description"));
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement(QStringLiteral("SID_DATA"));
            stream.writeCharacters(s.description);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            stream.writeStartElement(QStringLiteral("SID_NAME"));
            stream.writeCharacters(QStringLiteral("filename"));
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement(QStringLiteral("SID_DATA"));
            stream.writeCharacters(s.fileName);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            stream.writeStartElement(QStringLiteral("SID_NAME"));
            stream.writeCharacters(QStringLiteral("releaseinfo"));
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement(QStringLiteral("SID_DATA"));
            stream.writeCharacters(s.release);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement(QStringLiteral("SI_DATA"));
            stream.writeStartElement(QStringLiteral("SID_NAME"));
            stream.writeCharacters(QStringLiteral("title"));
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement(QStringLiteral("SID_DATA"));
            stream.writeCharacters(s.title);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeEndElement(); //STIG_INFO

            foreach (const CKLCheck &cc, _asset.GetCKLChecks(&s))
            {
                const STIGCheck sc = cc.GetSTIGCheck();
                stream.writeStartElement(QStringLiteral("VULN"));

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Vuln_Num"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.vulnNum);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Severity"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(GetSeverity(cc.GetSeverity(), false));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Group_Title"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.groupTitle);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Rule_ID"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.rule);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Rule_Ver"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.ruleVersion);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Rule_Title"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.title);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Vuln_Discuss"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.vulnDiscussion);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("IA_Controls"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.iaControls);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Check_Content"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.check);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Fix_Text"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.fix);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("False_Positives"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.falsePositives);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("False_Negatives"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.falseNegatives);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Documentable"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(PrintTrueFalse(sc.documentable));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Mitigations"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.mitigations);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Potential_Impact"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.potentialImpact);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Third_Party_Tools"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.thirdPartyTools);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Mitigation_Control"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.mitigationControl);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Responsibility"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.responsibility);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Security_Override_Guidance"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.severityOverrideGuidance);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Check_Content_Ref"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.checkContentRef);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("Weight"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(QString::number(sc.weight));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("STIGRef"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(s.title + " :: Version " + QString::number(s.version) + ", " + s.release);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement(QStringLiteral("STIG_DATA"));
                stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                stream.writeCharacters(QStringLiteral("TargetKey"));
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                stream.writeCharacters(sc.targetKey);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                foreach(CCI cci, sc.GetCCIs())
                {
                    stream.writeStartElement(QStringLiteral("STIG_DATA"));
                    stream.writeStartElement(QStringLiteral("VULN_ATTRIBUTE"));
                    stream.writeCharacters(QStringLiteral("CCI_REF"));
                    stream.writeEndElement(); //VULN_ATTRIBUTE
                    stream.writeStartElement(QStringLiteral("ATTRIBUTE_DATA"));
                    stream.writeCharacters(PrintCCI(cci));
                    stream.writeEndElement(); //ATTRIBUTE_DATA
                    stream.writeEndElement(); //STIG_DATA
                }

                stream.writeStartElement(QStringLiteral("STATUS"));
                stream.writeCharacters(GetStatus(cc.status, true));
                stream.writeEndElement(); //STATUS

                stream.writeStartElement(QStringLiteral("FINDING_DETAILS"));
                stream.writeCharacters(cc.findingDetails);
                stream.writeEndElement(); //FINDING_DETAILS

                stream.writeStartElement(QStringLiteral("COMMENTS"));
                stream.writeCharacters(cc.comments);
                stream.writeEndElement(); //COMMENTS

                stream.writeStartElement(QStringLiteral("SEVERITY_OVERRIDE"));
                stream.writeCharacters(GetSeverity(cc.severityOverride, false));
                stream.writeEndElement(); //SEVERITY_OVERRIDE

                stream.writeStartElement(QStringLiteral("SEVERITY_JUSTIFICATION"));
                stream.writeCharacters(cc.severityJustification);
                stream.writeEndElement(); //SEVERITY_JUSTIFICATION

                stream.writeEndElement(); //VULN
            }

            stream.writeEndElement(); //iSTIG
        }
        stream.writeEndElement(); //STIGS
        stream.writeEndElement(); //CHECKLIST
        stream.writeEndDocument();
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
    //make sure that something is selected
    if (count > 0)
    {
        DbManager db;
        db.DelayCommit(true);
        foreach (QListWidgetItem *i, selectedItems)
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
    if ((_asset.hostIP != ui->txtIP->text()) || (_asset.hostMAC != ui->txtMAC->text()) || (_asset.hostFQDN != ui->txtFQDN->text()))
    {
        DbManager db;
        _asset.hostIP = ui->txtIP->text();
        _asset.hostMAC = ui->txtMAC->text();
        _asset.hostFQDN = ui->txtFQDN->text();
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
    if (selectedItems.count() > 0)
    {
        foreach (QListWidgetItem *i, selectedItems)
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
    if (selectedItems.count() > 0)
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
    QList<STIG> stigs = _asset.GetSTIGs();
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
