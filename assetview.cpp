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

/*!
 * \class AssetView
 * \brief The STIGViewer-like display of an Asset's STIG, checks, and
 * compliance status.
 *
 * The AssetView is the main STIG compliance view for a singular
 * Asset. It enumerates the applicable checks, their compliance
 * status, and provides commentary fields for each of the checks.
 *
 * The AssetView is a tabbed page, created dynamically, and closeable
 * by the user.
 */

/*!
 * \brief AssetView::AssetView
 * \param parent
 *
 * Main constructor.
 */
AssetView::AssetView(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AssetView),
    _justification(),
    _updateStatus(false),
    _tabIndex(-1)
{
    ui->setupUi(this);

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
}

/*!
 * \overload AssetView()
 * \brief AssetView::AssetView
 * \param a
 * \param parent
 *
 * A new tab is created for the supplied Asset.
 */
AssetView::AssetView(const Asset &asset, QWidget *parent) : AssetView(parent)
{
    _asset = asset;
    Display();
}

/*!
 * Destructor.
 */
AssetView::~AssetView()
{
    foreach (QShortcut *shortcut, _shortcuts)
        delete shortcut;
    _shortcuts.clear();
    delete ui;
}

/*!
 * \brief AssetView::Display
 *
 * Shows the STIGs and CKL Checks for the selected Asset
 */
void AssetView::Display()
{
    SelectSTIGs();
    ShowChecks();
}

/*!
 * \brief AssetView::SelectSTIGs
 *
 * Marks the STIGs that are tied to the Asset as selected in the
 * list of all possible STIGs.
 */
void AssetView::SelectSTIGs()
{
    DbManager db;
    //ui->lstSTIGs->blockSignals(true);
    ui->lstSTIGs->clear();
    QList<STIG> stigs = _asset.STIGs();
    foreach (const STIG s, db.GetSTIGs())
    {
        QListWidgetItem *i = new QListWidgetItem(PrintSTIG(s));
        ui->lstSTIGs->addItem(i);
        i->setData(Qt::UserRole, QVariant::fromValue<STIG>(s));
        i->setSelected(stigs.contains(s));
    }
    //ui->lstSTIGs->blockSignals(false);
}

/*!
 * \brief AssetView::CountChecks
 *
 * Display/update the count of checks and their compliance statuses.
 */
void AssetView::CountChecks()
{
    ShowChecks(true);
}

/*!
 * \brief AssetView::ShowChecks
 * \param countOnly
 *
 * When \a countOnly is \c true, the number of checks and their
 * compliance statuses are updated. When \a countOnly is \c false,
 * the display of CKL Checks is also updated.
 */
void AssetView::ShowChecks(bool countOnly)
{
    if (!countOnly)
        ui->lstChecks->clear();
    int total = 0; //total checks
    int open = 0; //findings
    int closed = 0; //passed checks
    foreach(const CKLCheck c, _asset.CKLChecks())
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
        if (!countOnly)
        {
            //update the list of CKL checks
            QListWidgetItem *i = new QListWidgetItem(PrintCKLCheck(c));
            ui->lstChecks->addItem(i);
            i->setData(Qt::UserRole, QVariant::fromValue<CKLCheck>(c));
            SetItemColor(i, c.status, (c.severityOverride == Severity::none) ? c.STIGCheck().severity : c.severityOverride);
        }
    }
    ui->lblTotalChecks->setText(QString::number(total));
    ui->lblOpen->setText(QString::number(open));
    ui->lblNotAFinding->setText(QString::number(closed));
    if (!countOnly)
        ui->lstChecks->sortItems();
}

/*!
 * \brief AssetView::UpdateCKLCheck
 * \param cklCheck
 *
 * Updates the displayed information about the selected CKL check,
 * \a cc, with information from the database.
 */
void AssetView::UpdateCKLCheck(const CKLCheck &cklCheck)
{
    //write database elemnets to user interface

    //While reading ui elements, disable their ability to throw an event.
    ui->txtComments->blockSignals(true);
    ui->txtFindingDetails->blockSignals(true);
    ui->cboBoxStatus->blockSignals(true);
    ui->cboBoxSeverity->blockSignals(true);

    //write \a cc information to the user interface
    ui->cboBoxStatus->setCurrentText(GetStatus(cklCheck.status));
    ui->txtComments->clear();
    ui->txtComments->insertPlainText(cklCheck.comments);
    ui->txtFindingDetails->clear();
    ui->txtFindingDetails->insertPlainText(cklCheck.findingDetails);
    _justification = cklCheck.severityJustification;

    //see if the check has a category-level override
    UpdateSTIGCheck(cklCheck.STIGCheck());
    if (cklCheck.severityOverride != Severity::none)
        ui->cboBoxSeverity->setCurrentText(GetSeverity(cklCheck.severityOverride));

    //Now that the elements are updated from the DB, they can throw events again.
    ui->txtComments->blockSignals(false);
    ui->txtFindingDetails->blockSignals(false);
    ui->cboBoxStatus->blockSignals(false);
    ui->cboBoxSeverity->blockSignals(false);
}

/*!
 * \brief AssetView::UpdateSTIGCheck
 * \param stigCheck
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

/*!
 * \brief AssetView::SetTabIndex
 * \param index
 *
 * Keep up with which index this tab is in the interface.
 */
void AssetView::SetTabIndex(int index)
{
    _tabIndex = index;
}

/*!
 * \brief AssetView::CheckSelectedChanged
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

/*!
 * \brief AssetView::DeleteAsset
 *
 * Deletes this Asset from the database.
 */
void AssetView::DeleteAsset()
{
    //prompt user for confirmation of a destructive task
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm", "Are you sure you want to delete " + PrintAsset(_asset) + "?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes)
    {
        DbManager db;
        //remove all associated STIGs from this asset.
        foreach (const STIG &s, _asset.STIGs())
            db.DeleteSTIGFromAsset(s, _asset);
        db.DeleteAsset(_asset);
        if (_tabIndex > 0)
            emit CloseTab(_tabIndex);
    }
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

/*!
 * \brief AssetView::SaveCKL
 *
 * Save the selected Asset as a single CKL file.
 */
void AssetView::SaveCKL()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Save STIG/SRG Checklist", QDir::home().dirName(), "STIG Checklist (*.ckl)");
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly))
    {
        QXmlStreamWriter stream(&file);
        //xml for a CKL file
        stream.writeStartDocument("1.0");
        stream.writeComment("STIGQter :: " + QString(VERSION));
        stream.writeStartElement("CHECKLIST");
        stream.writeStartElement("ASSET");
        stream.writeStartElement("ROLE");
        stream.writeCharacters("None");
        stream.writeEndElement(); //ROLE
        stream.writeStartElement("ASSET_TYPE");
        stream.writeCharacters(_asset.assetType);
        stream.writeEndElement(); //ASSET_TYPE
        stream.writeStartElement("HOST_NAME");
        stream.writeCharacters(_asset.hostName);
        stream.writeEndElement(); //HOST_NAME
        stream.writeStartElement("HOST_IP");
        stream.writeCharacters(_asset.hostIP);
        stream.writeEndElement(); //HOST_IP
        stream.writeStartElement("HOST_MAC");
        stream.writeCharacters(_asset.hostMAC);
        stream.writeEndElement(); //HOST_MAC
        stream.writeStartElement("HOST_FQDN");
        stream.writeCharacters(_asset.hostFQDN);
        stream.writeEndElement(); //HOST_FQDN
        stream.writeStartElement("TECH_AREA");
        stream.writeCharacters(_asset.techArea);
        stream.writeEndElement(); //TECH_AREA
        stream.writeStartElement("TARGET_KEY");
        stream.writeCharacters(_asset.targetKey);
        stream.writeEndElement(); //TARGET_KEY
        stream.writeStartElement("WEB_OR_DATABASE");
        stream.writeCharacters(PrintTrueFalse(_a.webOrDB));
        stream.writeEndElement(); //WEB_OR_DATABASE
        stream.writeStartElement("WEB_DB_SITE");
        stream.writeCharacters(_asset.webDbSite);
        stream.writeEndElement(); //WEB_DB_SITE
        stream.writeStartElement("WEB_DB_INSTANCE");
        stream.writeCharacters(_asset.webDbInstance);
        stream.writeEndElement(); //WEB_DB_INSTANCE
        stream.writeEndElement(); //ASSET
        stream.writeStartElement("STIGS");
        foreach (const STIG &s, _asset.STIGs())
        {
            stream.writeStartElement("iSTIG");
            stream.writeStartElement("STIG_INFO");

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("version");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(QString::number(s.version));
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("stigid");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.benchmarkId);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("description");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.description);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("filename");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.fileName);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("releaseinfo");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.release);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeStartElement("SI_DATA");
            stream.writeStartElement("SID_NAME");
            stream.writeCharacters("title");
            stream.writeEndElement(); //SID_NAME
            stream.writeStartElement("SID_DATA");
            stream.writeCharacters(s.title);
            stream.writeEndElement(); //SID_DATA
            stream.writeEndElement(); //SI_DATA

            stream.writeEndElement(); //STIG_INFO

            foreach (const CKLCheck &cc, _asset.CKLChecks(&s))
            {
                const STIGCheck sc = cc.STIGCheck();
                stream.writeStartElement("VULN");

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Vuln_Num");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.vulnNum);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Severity");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(GetSeverity(cc.GetSeverity(), false));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Group_Title");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.groupTitle);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Rule_ID");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.rule);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Rule_Ver");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.ruleVersion);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Rule_Title");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.title);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Vuln_Discuss");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.vulnDiscussion);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("IA_Controls");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.iaControls);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Check_Content");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.check);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Fix_Text");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.fix);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("False_Positives");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.falsePositives);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("False_Negatives");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.falseNegatives);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Documentable");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(PrintTrueFalse(sc.documentable));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Mitigations");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.mitigations);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Potential_Impact");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.potentialImpact);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Third_Party_Tools");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.thirdPartyTools);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Mitigation_Control");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.mitigationControl);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Responsibility");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.responsibility);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Security_Override_Guidance");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.severityOverrideGuidance);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Check_Content_Ref");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.checkContentRef);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("Weight");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(QString::number(sc.weight));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("STIGRef");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(s.title + " :: Version " + QString::number(s.version) + ", " + s.release);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("TargetKey");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(sc.targetKey);
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STIG_DATA");
                stream.writeStartElement("VULN_ATTRIBUTE");
                stream.writeCharacters("CCI_REF");
                stream.writeEndElement(); //VULN_ATTRIBUTE
                stream.writeStartElement("ATTRIBUTE_DATA");
                stream.writeCharacters(PrintCCI(sc.CCI()));
                stream.writeEndElement(); //ATTRIBUTE_DATA
                stream.writeEndElement(); //STIG_DATA

                stream.writeStartElement("STATUS");
                stream.writeCharacters(GetStatus(cc.status, true));
                stream.writeEndElement(); //STATUS

                stream.writeStartElement("FINDING_DETAILS");
                stream.writeCharacters(cc.findingDetails);
                stream.writeEndElement(); //FINDING_DETAILS

                stream.writeStartElement("COMMENTS");
                stream.writeCharacters(cc.comments);
                stream.writeEndElement(); //COMMENTS

                stream.writeStartElement("SEVERITY_OVERRIDE");
                stream.writeCharacters(GetSeverity(cc.severityOverride, false));
                stream.writeEndElement(); //SEVERITY_OVERRIDE

                stream.writeStartElement("SEVERITY_JUSTIFICATION");
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

/*!
 * \brief AssetView::KeyShortcut
 * \param action
 *
 * When a keyboard shortcut is used, set the display element to
 * correspond.
 */
void AssetView::KeyShortcut(const Status &action)
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

/*!
 * \brief AssetView::UpdateCKLHelper
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
            CKLCheck cc = i->data(Qt::UserRole).value<CKLCheck>();
            //if multiple checks are selected, only update their status
            if (count < 2)
            {
                cc.comments = ui->txtComments->toPlainText();
                cc.findingDetails = ui->txtFindingDetails->toPlainText();
                Severity tmpSeverity = GetSeverity(ui->cboBoxSeverity->currentText());
                cc.severityOverride = (tmpSeverity == cc.STIGCheck().severity) ? cc.severityOverride = Severity::none : tmpSeverity;
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
}

/*!
 * \brief AssetView::UpdateCKL
 *
 * Detects when the user has made a change and been idle for a while.
 */
void AssetView::UpdateCKL()
{
    //avoid updating the database for every keypress. Wait for 9/50 of a second before saving
    //https://forum.qt.io/topic/97857/qplaintextedit-autosave-to-database
    _timer.start(180);
}

/*!
 * \brief AssetView::UpdateCKLStatus
 * \param val
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
            CKLCheck cc = i->data(Qt::UserRole).value<CKLCheck>();
            STIGCheck sc = cc.STIGCheck();
            SetItemColor(i, stat, (cc.severityOverride == Severity::none) ? sc.severity : cc.severityOverride);
        }
        _updateStatus = true;
        UpdateCKL();
    }
}

/*!
 * \brief AssetView::UpdateCKLSeverity
 * \param val
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
        CKLCheck cc = i->data(Qt::UserRole).value<CKLCheck>();
        STIGCheck sc = cc.STIGCheck();
        Severity tmpSeverity = GetSeverity(val);
        if (sc.severity != tmpSeverity)
        {
            if (tmpSeverity == Severity::none)
            {
                QMessageBox::warning(nullptr, "Removed Severity Override", "Severity override is removed; findings cannot be downgraded to CAT IV.");
                _justification = "";
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

/*!
 * \brief AssetView::UpdateSTIGs
 *
 * Handle the selection of which STIGs are included with the viewed
 * Asset;
 */
void AssetView::UpdateSTIGs()
{
    DbManager db;
    QList<STIG> stigs = _asset.STIGs();
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
            QMessageBox::StandardButton confirm = QMessageBox::question(this, "Confirm STIG Removal", "Really delete the " + PrintSTIG(s) + " stig from " + PrintAsset(_asset) + "?",
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

/*!
 * \brief AssetView::SetItemColor
 * \param i
 * \param stat
 * \param sev
 *
 * Sets the QListWidgetItem's color so that attention is drawn to it,
 * particularly when the check is non-compliant.
 */
void AssetView::SetItemColor(QListWidgetItem *i, const Status &stat, const Severity &sev)
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

/*!
 * \brief AssetView::CheckSelected
 *
 * When a new CKL check is selected, make sure that the previously displayed
 * one has updated its elements correctly.
 */
void AssetView::CheckSelected(QListWidgetItem *current, QListWidgetItem *previous [[maybe_unused]])
{
    if (current)
    {
        CKLCheck cc = current->data(Qt::UserRole).value<CKLCheck>();
        DbManager db;
        UpdateCKLCheck(db.GetCKLCheck(cc));
    }
}
