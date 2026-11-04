// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QPointer>
class STIGQter;
class AssetView;
class STIGEdit;
class TabViewWidget;
class UiScenarios {
public:
    static void phase1(STIGQter *window);
    static void phase2(STIGQter *window);
    static void phase3(STIGQter *window);
    static void phase4(STIGQter *window);
    static void phase5(STIGQter *window);
private:
    static int step;
    static bool wait(STIGQter *window);
    static void runTab(TabViewWidget *tab, STIGQter *window);
    static void runAssetView(QPointer<AssetView> subject, STIGQter *window);
    static void runSTIGEdit(STIGEdit *subject, STIGQter *window);
};
