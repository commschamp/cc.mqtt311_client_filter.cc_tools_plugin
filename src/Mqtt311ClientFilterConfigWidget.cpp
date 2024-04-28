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

#include "Mqtt311ClientFilterConfigWidget.h"

#include "Mqtt311ClientFilterSubConfigWidget.h"

#include <cassert>

#include <QtCore/QtGlobal>

namespace cc_plugin_mqtt311_client_filter
{

namespace 
{

void deleteAllWidgetsFrom(QLayout& layout)
{
    while (true) {
        auto* child = layout.takeAt(0);
        if (child == nullptr) {
            break;
        }

        delete child->widget();
        delete child;
    }
}

} // namespace 
    

Mqtt311ClientFilterConfigWidget::Mqtt311ClientFilterConfigWidget(Mqtt311ClientFilter& filter, QWidget* parentObj) :
    Base(parentObj),
    m_filter(filter)
{
    m_ui.setupUi(this);

    auto subsLayout = new QVBoxLayout;
    m_ui.m_subsWidget->setLayout(subsLayout);

    refresh();

    connect(
        &m_filter, &Mqtt311ClientFilter::sigConfigChanged,
        this, &Mqtt311ClientFilterConfigWidget::refresh);     

    connect(
        m_ui.m_respTimeoutSpinBox, qOverload<int>(&QSpinBox::valueChanged),
        this, &Mqtt311ClientFilterConfigWidget::respTimeoutUpdated);    

    connect(
        m_ui.m_clientIdLineEdit, &QLineEdit::textChanged,
        this, &Mqtt311ClientFilterConfigWidget::clientIdUpdated);

    connect(
        m_ui.m_usernameLineEdit, &QLineEdit::textChanged,
        this, &Mqtt311ClientFilterConfigWidget::usernameUpdated);        

    connect(
        m_ui.m_passwordLineEdit, &QLineEdit::textChanged,
        this, &Mqtt311ClientFilterConfigWidget::passwordUpdated); 

    connect(
        m_ui.m_passwordShowHidePushButton,  &QPushButton::clicked,
        this, &Mqtt311ClientFilterConfigWidget::passwordShowHideClicked);               

    connect(
        m_ui.m_keepAliveSpinBox, qOverload<int>(&QSpinBox::valueChanged),
        this, &Mqtt311ClientFilterConfigWidget::keepAliveUpdated);    

    connect(
        m_ui.m_cleanSessionComboBox, qOverload<int>(&QComboBox::currentIndexChanged),
        this, &Mqtt311ClientFilterConfigWidget::forcedCleanSessionUpdated);           

    connect(
        m_ui.m_pubTopicLineEdit, &QLineEdit::textChanged,
        this, &Mqtt311ClientFilterConfigWidget::pubTopicUpdated);        

    connect(
        m_ui.m_pubQosSpinBox, qOverload<int>(&QSpinBox::valueChanged),
        this, &Mqtt311ClientFilterConfigWidget::pubQosUpdated);   

    connect(
        m_ui.m_addSubPushButton, &QPushButton::clicked,
        this, &Mqtt311ClientFilterConfigWidget::addSubscribe);           
}

Mqtt311ClientFilterConfigWidget::~Mqtt311ClientFilterConfigWidget() noexcept = default;

void Mqtt311ClientFilterConfigWidget::refresh()
{
    deleteAllWidgetsFrom(*(m_ui.m_subsWidget->layout()));

    for (auto& subConfig : m_filter.config().m_subscribes) {
        addSubscribeWidget(subConfig);
    }    

    m_ui.m_respTimeoutSpinBox->setValue(m_filter.config().m_respTimeout);
    m_ui.m_clientIdLineEdit->setText(m_filter.config().m_clientId);
    m_ui.m_usernameLineEdit->setText(m_filter.config().m_username);
    m_ui.m_passwordLineEdit->setText(m_filter.config().m_password);
    m_ui.m_keepAliveSpinBox->setValue(static_cast<int>(m_filter.config().m_keepAlive));
    m_ui.m_cleanSessionComboBox->setCurrentIndex(static_cast<int>(m_filter.config().m_forcedCleanSession));
    m_ui.m_pubTopicLineEdit->setText(m_filter.config().m_pubTopic);
    m_ui.m_pubQosSpinBox->setValue(m_filter.config().m_pubQos);

    refreshSubscribes();
}

void Mqtt311ClientFilterConfigWidget::respTimeoutUpdated(int val)
{
    m_filter.config().m_respTimeout = static_cast<unsigned>(val);
}

void Mqtt311ClientFilterConfigWidget::clientIdUpdated(const QString& val)
{
    if (m_filter.config().m_clientId == val) {
        return;
    }

    m_filter.config().m_clientId = val;
    m_filter.forceCleanSession();
}

void Mqtt311ClientFilterConfigWidget::usernameUpdated(const QString& val)
{
    m_filter.config().m_username = val;
}

void Mqtt311ClientFilterConfigWidget::passwordUpdated(const QString& val)
{
    m_filter.config().m_password = val;
}

void Mqtt311ClientFilterConfigWidget::passwordShowHideClicked(bool checked)
{
    auto mode = QLineEdit::Password;
    auto buttonText = tr("Show");
    if (checked) {
        mode = QLineEdit::Normal;
        buttonText = tr("Hide");
    }
    
    m_ui.m_passwordLineEdit->setEchoMode(mode);
    m_ui.m_passwordShowHidePushButton->setText(buttonText);    
}

void Mqtt311ClientFilterConfigWidget::keepAliveUpdated(int val)
{
    m_filter.config().m_keepAlive = static_cast<unsigned>(val);
}

void Mqtt311ClientFilterConfigWidget::forcedCleanSessionUpdated(int val)
{
    m_filter.config().m_forcedCleanSession = (val > 0);
}

void Mqtt311ClientFilterConfigWidget::pubTopicUpdated(const QString& val)
{
    m_filter.config().m_pubTopic = val;
}

void Mqtt311ClientFilterConfigWidget::pubQosUpdated(int val)
{
    m_filter.config().m_pubQos = val;
}

void Mqtt311ClientFilterConfigWidget::addSubscribe()
{
    auto& subs = m_filter.config().m_subscribes;
    subs.resize(subs.size() + 1U);
    addSubscribeWidget(subs.back());
    refreshSubscribes();
}

void Mqtt311ClientFilterConfigWidget::refreshSubscribes()
{
    bool subscribesVisible = !m_filter.config().m_subscribes.empty();
    m_ui.m_subsWidget->setVisible(subscribesVisible);
}

void Mqtt311ClientFilterConfigWidget::addSubscribeWidget(SubConfig& config)
{
    auto* widget = new Mqtt311ClientFilterSubConfigWidget(m_filter, config, this);
    connect(
        widget, &QObject::destroyed,
        this,
        [this](QObject*)
        {
            refreshSubscribes();
        });

    auto* subsLayout = qobject_cast<QVBoxLayout*>(m_ui.m_subsWidget->layout());
    assert(subsLayout != nullptr);
    subsLayout->addWidget(widget); 
}

}  // namespace cc_plugin_mqtt311_client_filter


