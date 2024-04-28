//
// Copyright 2024 - 2025 (C). Alex Robenko. All rights reserved.
//

// This file is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.


#pragma once

#include "ui_Mqtt311ClientFilterConfigWidget.h"

#include "Mqtt311ClientFilter.h"

#include <QtWidgets/QWidget>


namespace cc_plugin_mqtt311_client_filter
{

class Mqtt311ClientFilterConfigWidget : public QWidget
{
    Q_OBJECT
    using Base = QWidget;

public:
    explicit Mqtt311ClientFilterConfigWidget(Mqtt311ClientFilter& filter, QWidget* parentObj = nullptr);
    ~Mqtt311ClientFilterConfigWidget() noexcept;

private slots:
    void refresh();
    void respTimeoutUpdated(int val);
    void clientIdUpdated(const QString& val);
    void usernameUpdated(const QString& val);
    void passwordUpdated(const QString& val);
    void passwordShowHideClicked(bool checked);
    void keepAliveUpdated(int val);
    void forcedCleanSessionUpdated(int val);
    void pubTopicUpdated(const QString& val);
    void pubQosUpdated(int val);
    void addSubscribe();

private:
    using SubConfig = Mqtt311ClientFilter::SubConfig;

    void refreshSubscribes();
    void addSubscribeWidget(SubConfig& config);    

    Mqtt311ClientFilter& m_filter;
    Ui::Mqtt311ClientFilterConfigWidget m_ui;
};

}  // namespace cc_plugin_mqtt311_client_filter


