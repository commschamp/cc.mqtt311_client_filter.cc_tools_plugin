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

#include "Mqtt311ClientFilterPlugin.h"

#include "Mqtt311ClientFilter.h"
#include "Mqtt311ClientFilterConfigWidget.h"

#include <cassert>
#include <memory>
#include <type_traits>

namespace cc_plugin_mqtt311_client_filter
{

namespace 
{

const QString MainConfigKey("cc_plugin_mqtt311_client_filter");
const QString RespTimeoutSubKey("resp_timeout");
const QString ClientIdSubKey("client_id");
const QString UsernameSubKey("username");
const QString PasswordSubKey("password");
const QString KeepAliveKey("keep_alive");
const QString TopicAliasMaxKey("topic_alias_max");
const QString ForceCleanSessionSubKey("force_clean_session");
const QString PubTopicSubKey("pub_topic");
const QString PubQosSubKey("pub_qos");
const QString SubTopicSubKey("sub_topic");
const QString SubQosSubKey("sub_qos");
const QString SubscribesSubKey("subscribes");


template <typename T>
void getFromConfigMap(const QVariantMap& subConfig, const QString& key, T& val)
{
    using Type = std::decay_t<decltype(val)>;
    auto var = subConfig.value(key);
    if (var.isValid() && var.canConvert<Type>()) {
        val = var.value<Type>();
    }    
}

QVariantMap toVariantMap(const Mqtt311ClientFilter::SubConfig& config)
{
    QVariantMap result;
    result[SubTopicSubKey] = config.m_topic;
    result[SubQosSubKey] = config.m_maxQos;
    return result;
}

void fromVariantMap(const QVariantMap& map, Mqtt311ClientFilter::SubConfig& config)
{
    getFromConfigMap(map, SubTopicSubKey, config.m_topic);
    getFromConfigMap(map, SubQosSubKey, config.m_maxQos);
}

QVariantList toVariantList(const Mqtt311ClientFilter::SubConfigsList& configsList)
{
    QVariantList result;
    for (auto& info : configsList) {
        result.append(toVariantMap(info));
    }
    return result;
}

template <typename T>
void getListFromConfigMap(const QVariantMap& subConfig, const QString& key, T& list)
{
    list.clear();

    auto var = subConfig.value(key);
    if ((!var.isValid()) || (!var.canConvert<QVariantList>())) {
        return;
    }    

    auto varList = var.value<QVariantList>();
    for (auto& elemVar : varList) {

        if ((!elemVar.isValid()) || (!elemVar.canConvert<QVariantMap>())) {
            return;
        }            

        auto varMap = elemVar.value<QVariantMap>();

        list.resize(list.size() + 1U);
        fromVariantMap(varMap, list.back());
    }
}

} // namespace 
    

Mqtt311ClientFilterPlugin::Mqtt311ClientFilterPlugin()
{
    pluginProperties()
        .setFiltersCreateFunc(
            [this]()
            {
                createFilterIfNeeded();
                cc_tools_qt::PluginProperties::ListOfFilters result;
                result.append(m_filter);
                return result;
            })
        .setConfigWidgetCreateFunc(
            [this]()
            {
                createFilterIfNeeded();
                return new Mqtt311ClientFilterConfigWidget(*m_filter);
            })            
        ;
}

Mqtt311ClientFilterPlugin::~Mqtt311ClientFilterPlugin() noexcept = default;

void Mqtt311ClientFilterPlugin::getCurrentConfigImpl(QVariantMap& config)
{
    createFilterIfNeeded();
    assert(m_filter);

    QVariantMap subConfig;
    subConfig.insert(RespTimeoutSubKey, m_filter->config().m_respTimeout);
    subConfig.insert(ClientIdSubKey, m_filter->config().m_clientId);
    subConfig.insert(UsernameSubKey, m_filter->config().m_username);
    subConfig.insert(PasswordSubKey, m_filter->config().m_password);
    subConfig.insert(KeepAliveKey, m_filter->config().m_keepAlive);
    subConfig.insert(ForceCleanSessionSubKey, m_filter->config().m_forcedCleanSession);
    subConfig.insert(PubTopicSubKey, m_filter->config().m_pubTopic);
    subConfig.insert(PubQosSubKey, m_filter->config().m_pubQos);
    subConfig.insert(SubscribesSubKey, toVariantList(m_filter->config().m_subscribes));
    config.insert(MainConfigKey, QVariant::fromValue(subConfig));
}

void Mqtt311ClientFilterPlugin::reconfigureImpl(const QVariantMap& config)
{
    auto subConfigVar = config.value(MainConfigKey);
    if ((!subConfigVar.isValid()) || (!subConfigVar.canConvert<QVariantMap>())) {
        return;
    }

    createFilterIfNeeded();
    assert(m_filter);

    auto subConfig = subConfigVar.value<QVariantMap>();

    getFromConfigMap(subConfig, RespTimeoutSubKey, m_filter->config().m_respTimeout);
    getFromConfigMap(subConfig, ClientIdSubKey, m_filter->config().m_clientId);
    getFromConfigMap(subConfig, UsernameSubKey, m_filter->config().m_username);
    getFromConfigMap(subConfig, PasswordSubKey, m_filter->config().m_password);
    getFromConfigMap(subConfig, KeepAliveKey, m_filter->config().m_keepAlive);
    getFromConfigMap(subConfig, ForceCleanSessionSubKey, m_filter->config().m_forcedCleanSession);
    getFromConfigMap(subConfig, PubTopicSubKey, m_filter->config().m_pubTopic);
    getFromConfigMap(subConfig, PubQosSubKey, m_filter->config().m_pubQos);
    getListFromConfigMap(subConfig, SubscribesSubKey, m_filter->config().m_subscribes);
}

void Mqtt311ClientFilterPlugin::applyInterPluginConfigImpl(const QVariantMap& props)
{
    createFilterIfNeeded();
    m_filter->applyInterPluginConfig(props);
}

void Mqtt311ClientFilterPlugin::createFilterIfNeeded()
{
    if (m_filter) {
        return;
    }

    m_filter = makeMqtt311ClientFilter();
}

}  // namespace cc_plugin_mqtt311_client_filter


