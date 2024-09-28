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

#include "Mqtt311ClientFilter.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QList>
#include <QtCore/QVariant>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <limits>
#include <iostream>
#include <string>

namespace cc_plugin_mqtt311_client_filter
{

namespace 
{

inline Mqtt311ClientFilter* asThis(void* data)
{
    return reinterpret_cast<Mqtt311ClientFilter*>(data);
}

const QString& topicProp()
{
    static const QString Str("mqtt311.topic");
    return Str;
}

const QString& aliasTopicProp()
{
    static const QString Str("mqtt.topic");
    return Str;
}

const QString& qosProp()
{
    static const QString Str("mqtt311.qos");
    return Str;
}

const QString& aliasQosProp()
{
    static const QString Str("mqtt.qos");
    return Str;
}

const QString& retainedProp()
{
    static const QString Str("mqtt311.retained");
    return Str;    
}

const QString& aliasRetainedProp()
{
    static const QString Str("mqtt.retained");
    return Str;    
}

const QString& clientProp()
{
    static const QString Str("mqtt311.client");
    return Str;    
}

const QString& aliasClientProp()
{
    static const QString Str("mqtt.client");
    return Str;    
}

const QString& usernameProp()
{
    static const QString Str("mqtt311.username");
    return Str;    
}

const QString& aliasUsernameProp()
{
    static const QString Str("mqtt.username");
    return Str;    
}

const QString& passwordProp()
{
    static const QString Str("mqtt311.password");
    return Str;    
}

const QString& aliasPasswordProp()
{
    static const QString Str("mqtt.password");
    return Str;    
}

const QString& pubTopicProp()
{
    static const QString Str("mqtt311.pub_topic");
    return Str;    
}

const QString& aliasPubTopicProp()
{
    static const QString Str("mqtt.pub_topic");
    return Str;    
}

const QString& pubQosProp()
{
    static const QString Str("mqtt311.pub_qos");
    return Str;    
}

const QString& aliasPubQosProp()
{
    static const QString Str("mqtt.pub_qos");
    return Str;    
}

const QString& subscribesProp()
{
    static const QString Str("mqtt311.subscribes");
    return Str;    
}

const QString& aliasSubscribesProp()
{
    static const QString Str("mqtt.subscribes");
    return Str;    
}

const QString& subscribesRemoveProp()
{
    static const QString Str("mqtt311.subscribes_remove");
    return Str;    
}

const QString& aliasSubscribesRemoveProp()
{
    static const QString Str("mqtt.subscribes_remove");
    return Str;    
}

const QString& subscribesClearProp()
{
    static const QString Str("mqtt311.subscribes_clear");
    return Str;    
}

const QString& aliasSubscribesClearProp()
{
    static const QString Str("mqtt.subscribes_clear");
    return Str;    
}

const QString& topicSubProp()
{
    static const QString Str("topic");
    return Str;
}

const QString& qosSubProp()
{
    static const QString Str("qos");
    return Str;
}

std::string getOutgoingTopic(const QVariantMap& props, const QString configVal)
{
    if (props.contains(topicProp())) {
        return props[topicProp()].value<QString>().toStdString();
    }

    if (props.contains(aliasTopicProp())) {
        return props[aliasTopicProp()].value<QString>().toStdString();
    }

    return configVal.toStdString();
}

int getOutgoingQos(const QVariantMap& props, int configVal)
{
    if (props.contains(qosProp())) {
        return props[qosProp()].value<int>();
    }

    if (props.contains(aliasQosProp())) {
        return props[aliasQosProp()].value<int>();
    }

    return configVal;
}

bool getOutgoingRetained(const QVariantMap& props)
{
    if (props.contains(retainedProp())) {
        return props[retainedProp()].value<bool>();
    }

    if (props.contains(aliasRetainedProp())) {
        return props[aliasRetainedProp()].value<bool>();
    }    

    return false;
}

const QString& errorCodeStr(CC_Mqtt311ErrorCode ec)
{
    static const QString Map[] = {
        /* CC_Mqtt311ErrorCode_Success */ "Success",
        /* CC_Mqtt311ErrorCode_InternalError */ "Internal Error",
        /* CC_Mqtt311ErrorCode_NotIntitialized */ "Not Initialized",
        /* CC_Mqtt311ErrorCode_Busy */ "Busy",
        /* CC_Mqtt311ErrorCode_NotConnected */ "Not Connected",
        /* CC_Mqtt311ErrorCode_AlreadyConnected */ "Already Connected",
        /* CC_Mqtt311ErrorCode_BadParam */ "Bad Parameter",
        /* CC_Mqtt311ErrorCode_InsufficientConfig */ "Insufficient Config",
        /* CC_Mqtt311ErrorCode_OutOfMemory */ "Out of Memory",
        /* CC_Mqtt311ErrorCode_BufferOverflow */ "Buffer Overflow",
        /* CC_Mqtt311ErrorCode_NotSupported */ "Feature is Not Supported",
        /* CC_Mqtt311ErrorCode_RetryLater */ "Retry later",
        /* CC_Mqtt311ErrorCode_Terminating */ "Terminating",
        /* CC_Mqtt311ErrorCode_NetworkDisconnected */ "Network is Disconnected",
        /* CC_Mqtt311ErrorCode_PreparationLocked */ "Preparation Locked",
    };
    static const std::size_t MapSize = std::extent<decltype(Map)>::value;
    static_assert(MapSize == CC_Mqtt311ErrorCode_ValuesLimit);

    auto idx = static_cast<unsigned>(ec);
    if (MapSize <= idx) {
        static const QString UnknownStr("Unknown");
        return UnknownStr;
    }

    return Map[idx];
}

const QString& statusStr(CC_Mqtt311AsyncOpStatus status)
{
    static const QString Map[] = {
        /* CC_Mqtt311AsyncOpStatus_Complete */ "Complete",
        /* CC_Mqtt311AsyncOpStatus_InternalError */ "Internal Error",
        /* CC_Mqtt311AsyncOpStatus_Timeout */ "Timeout",
        /* CC_Mqtt311AsyncOpStatus_ProtocolError */ "Protocol Error",
        /* CC_Mqtt311AsyncOpStatus_Aborted */ "Aborted",
        /* CC_Mqtt311AsyncOpStatus_BrokerDisconnected */ "Broker Disconnected",
        /* CC_Mqtt311AsyncOpStatus_OutOfMemory */ "Out of Memory",
        /* CC_Mqtt311AsyncOpStatus_BadParam */ "Bad Parameter",
    };
    static const std::size_t MapSize = std::extent<decltype(Map)>::value;
    static_assert(MapSize == CC_Mqtt311AsyncOpStatus_ValuesLimit);

    auto idx = static_cast<unsigned>(status);
    if (MapSize <= idx) {
        static const QString UnknownStr("Unknown");
        return UnknownStr;
    }

    return Map[idx];
}

std::vector<std::uint8_t> parsePassword(const QString& password)
{
    std::vector<std::uint8_t> result;
    result.reserve(password.size());

    for (auto idx = 0; idx < password.size();) {
        if (((idx + 1) < password.size()) && (password[idx] == '\\') && (password[idx + 1] == '\\')) {
            result.push_back(static_cast<std::uint8_t>('\''));
            idx += 2;
            continue;
        }

        if ((password.size() <= (idx + 4)) || 
            (password[idx] != '\\') || 
            (password[idx + 1] != 'x')) {
            result.push_back(static_cast<std::uint8_t>(password[idx].cell()));
            idx += 1;
            continue;
        }

        result.push_back(static_cast<std::uint8_t>(password.mid(idx + 2, 2).toUInt(nullptr, 16)));
        idx += 4;
    }

    return result;
}

} // namespace 
    

Mqtt311ClientFilter::Mqtt311ClientFilter() :
    m_client(::cc_mqtt311_client_alloc())
{
    m_timer.setSingleShot(true);
    connect(
        &m_timer, &QTimer::timeout,
        this, &Mqtt311ClientFilter::doTick);

    ::cc_mqtt311_client_set_send_output_data_callback(m_client.get(), &Mqtt311ClientFilter::sendDataCb, this);
    ::cc_mqtt311_client_set_broker_disconnect_report_callback(m_client.get(), &Mqtt311ClientFilter::brokerDisconnectedCb, this);
    ::cc_mqtt311_client_set_message_received_report_callback(m_client.get(), &Mqtt311ClientFilter::messageReceivedCb, this);
    ::cc_mqtt311_client_set_next_tick_program_callback(m_client.get(), &Mqtt311ClientFilter::nextTickProgramCb, this);
    ::cc_mqtt311_client_set_cancel_next_tick_wait_callback(m_client.get(), &Mqtt311ClientFilter::cancelTickProgramCb, this);
    ::cc_mqtt311_client_set_error_log_callback(m_client.get(), &Mqtt311ClientFilter::errorLogCb, nullptr);

    m_config.m_respTimeout = ::cc_mqtt311_client_get_default_response_timeout(m_client.get());
}

Mqtt311ClientFilter::~Mqtt311ClientFilter() noexcept = default;

bool Mqtt311ClientFilter::startImpl()
{
    auto ec = ::cc_mqtt311_client_set_default_response_timeout(m_client.get(), m_config.m_respTimeout);
    if (ec != CC_Mqtt311ErrorCode_Success) {
        reportError(tr("Failed to update MQTT311 default response timeout"));
        return false;
    }    

    return true; 
}

void Mqtt311ClientFilter::stopImpl()
{
    if (!::cc_mqtt311_client_is_connected(m_client.get())) {
        return;
    }

    auto ec = cc_mqtt311_client_disconnect(m_client.get());
    if (ec != CC_Mqtt311ErrorCode_Success) {
        reportError(tr("Failed to send disconnect with error: ") + errorCodeStr(ec));
        return;
    }    
}

QList<cc_tools_qt::DataInfoPtr> Mqtt311ClientFilter::recvDataImpl(cc_tools_qt::DataInfoPtr dataPtr)
{
    m_recvData.clear();
    m_recvDataPtr = std::move(dataPtr);
    m_inData.insert(m_inData.end(), m_recvDataPtr->m_data.begin(), m_recvDataPtr->m_data.end());
    auto consumed = ::cc_mqtt311_client_process_data(m_client.get(), m_inData.data(), static_cast<unsigned>(m_inData.size()));
    if (3 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): consumed bytes: " << consumed << "/" << m_inData.size() << std::endl;
    }     
    assert(consumed <= m_inData.size());
    m_inData.erase(m_inData.begin(), m_inData.begin() + consumed);
    m_recvDataPtr.reset();
    return std::move(m_recvData);
}

QList<cc_tools_qt::DataInfoPtr> Mqtt311ClientFilter::sendDataImpl(cc_tools_qt::DataInfoPtr dataPtr)
{
    m_sendData.clear();

    if (!m_socketConnected) {
        reportError(tr("Cannot send MQTT311 data when socket is not connected"));
        return m_sendData;
    }

    if (!::cc_mqtt311_client_is_connected(m_client.get())) {
        m_pendingData.push_back(std::move(dataPtr));
        return m_sendData;
    }

    auto& props = dataPtr->m_extraProperties;
    std::string topic = getOutgoingTopic(props, m_config.m_pubTopic);
    props[topicProp()] = QString::fromStdString(topic);
    
    auto qos = getOutgoingQos(props, m_config.m_pubQos);
    props[qosProp()] = qos;

    auto retained = getOutgoingRetained(props);
    props[retainedProp()] = retained;

    if (2 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): publish: " << topic << std::endl;
    }    

    CC_Mqtt311ErrorCode ec = CC_Mqtt311ErrorCode_Success;
    CC_Mqtt311PublishHandle publish = ::cc_mqtt311_client_publish_prepare(m_client.get(), &ec);
    if (publish == NULL) {
        reportError(tr("Publish allocation failed with error: ") + errorCodeStr(ec));
        return m_sendData;
    }

    auto config = CC_Mqtt311PublishConfig();
    ::cc_mqtt311_client_publish_init_config(&config);

    config.m_topic = topic.c_str();
    config.m_data = dataPtr->m_data.data();
    config.m_dataLen = static_cast<decltype(config.m_dataLen)>(dataPtr->m_data.size());
    config.m_qos = static_cast<decltype(config.m_qos)>(qos);    
    config.m_retain = retained;
    ec = ::cc_mqtt311_client_publish_config(publish, &config);
    if (ec != CC_Mqtt311ErrorCode_Success) {
        reportError(tr("Failed to configure MQTT311 publish with error: ") + errorCodeStr(ec));
        return m_sendData;
    }    

    m_sendDataPtr = std::move(dataPtr);

    ec = ::cc_mqtt311_client_publish_send(publish, &publishCompleteCb, this);
    if (ec != CC_Mqtt311ErrorCode_Success) {
        reportError(tr("Failed to send MQTT311 publish with error: ") + errorCodeStr(ec));
        m_sendDataPtr.reset();
        return m_sendData;        
    }

    m_sendDataPtr.reset();
    return std::move(m_sendData);
}

void Mqtt311ClientFilter::socketConnectionReportImpl(bool connected)
{
    m_socketConnected = connected;
    if (connected) {
        socketConnected();
        return;
    }

    socketDisconnected();
}

void Mqtt311ClientFilter::applyInterPluginConfigImpl(const QVariantMap& props)
{
    bool updated = false;

    {
        static const QString* ClientProps[] = {
            &aliasClientProp(),
            &clientProp(),
        };

        for (auto* p : ClientProps) {
            auto var = props.value(*p);
            if ((var.isValid()) && (var.canConvert<QString>())) {
                m_config.m_clientId = var.value<QString>();
                updated = true;
            }
        }
    }

    {
        static const QString* UsernameProps[] = {
            &aliasUsernameProp(),
            &usernameProp(),
        };

        for (auto* p : UsernameProps) {
            auto var = props.value(*p);
            if ((var.isValid()) && (var.canConvert<QString>())) {
                m_config.m_username = var.value<QString>();
                updated = true;
            }
        }
    }
    
    {
        static const QString* PasswordProps[] = {
            &aliasPasswordProp(),
            &passwordProp(),
        };

        for (auto* p : PasswordProps) {
            auto var = props.value(*p);
            if ((var.isValid()) && (var.canConvert<QString>())) {
                m_config.m_password = var.value<QString>();
                updated = true;
            }
        }  
    }

    {
        static const QString* PubTopicProps[] = {
            &aliasPubTopicProp(),
            &pubTopicProp(),
        };

        for (auto* p : PubTopicProps) {
            auto var = props.value(*p);
            if ((var.isValid()) && (var.canConvert<QString>())) {
                m_config.m_pubTopic = var.value<QString>();
                updated = true;
            }
        }  
    }  

    {
        static const QString* PubQosProps[] = {
            &aliasPubQosProp(),
            &pubQosProp(),
        };

        for (auto* p : PubQosProps) {
            auto var = props.value(*p);
            if ((var.isValid()) && (var.canConvert<int>())) {
                m_config.m_pubQos = var.value<int>();
                updated = true;
            }
        }  
    }  

    {
        static const QString* SubscribesRemoveProps[] = {
            &aliasSubscribesRemoveProp(),
            &subscribesRemoveProp(),
        };

        for (auto* p : SubscribesRemoveProps) {
            auto var = props.value(*p);
            if ((!var.isValid()) || (!var.canConvert<QVariantList>())) {
                continue;
            }

            auto subList = var.value<QVariantList>();

            for (auto idx = 0; idx < subList.size(); ++idx) {
                auto& subVar = subList[idx];
                if ((!subVar.isValid()) || (!subVar.canConvert<QVariantMap>())) {
                    continue;
                }

                auto subMap = subVar.value<QVariantMap>();
                auto topicVar = subMap.value(topicSubProp());
                if ((!topicVar.isValid()) || (!topicVar.canConvert<QString>())) {
                    continue;
                }

                auto topic = topicVar.value<QString>();

                auto iter = 
                    std::find_if(
                        m_config.m_subscribes.begin(), m_config.m_subscribes.end(),
                        [&topic](const auto& info)
                        {
                            return topic == info.m_topic;
                        });
                
                if (iter != m_config.m_subscribes.end()) {
                    m_config.m_subscribes.erase(iter);
                    updated = true;
                    forceCleanSession();                    
                }
            }
        }  
    }  

    {
        static const QString* SubscribesClearProps[] = {
            &aliasSubscribesClearProp(),
            &subscribesClearProp(),
        };

        for (auto* p : SubscribesClearProps) {
            auto var = props.value(*p);
            if ((!var.isValid()) || (!var.canConvert<bool>())) {
                continue;
            }

            if ((!var.value<bool>()) || (m_config.m_subscribes.empty())) {
                continue;
            }

            m_config.m_subscribes.clear();
            updated = true;
        }  
    }           

    {
        static const QString* SubscribesProps[] = {
            &aliasSubscribesProp(),
            &subscribesProp(),
        };

        for (auto* p : SubscribesProps) {
            auto var = props.value(*p);
            if ((!var.isValid()) || (!var.canConvert<QVariantList>())) {
                continue;
            }

            auto subList = var.value<QVariantList>();

            for (auto idx = 0; idx < subList.size(); ++idx) {
                auto& subVar = subList[idx];
                if ((!subVar.isValid()) || (!subVar.canConvert<QVariantMap>())) {
                    continue;
                }

                auto subMap = subVar.value<QVariantMap>();
                auto topicVar = subMap.value(topicSubProp());
                if ((!topicVar.isValid()) || (!topicVar.canConvert<QString>())) {
                    continue;
                }

                auto topic = topicVar.value<QString>();

                auto iter = 
                    std::find_if(
                        m_config.m_subscribes.begin(), m_config.m_subscribes.end(),
                        [&topic](const auto& info)
                        {
                            return topic == info.m_topic;
                        });
                
                if (iter == m_config.m_subscribes.end()) {
                    iter = m_config.m_subscribes.insert(m_config.m_subscribes.end(), SubConfig());
                    iter->m_topic = topic;
                }

                auto& subConfig = *iter;
                auto qosVar = subMap.value(qosSubProp());
                if (qosVar.isValid() && qosVar.canConvert<int>()) {
                    subConfig.m_maxQos = qosVar.value<int>();
                }
            }
            
            updated = true;
            forceCleanSession();
        }  
    }              

    if (updated) {
        emit sigConfigChanged();
    }
}

const char* Mqtt311ClientFilter::debugNameImpl() const
{
    return "mqtt v3.1.1 client filter";
}

void Mqtt311ClientFilter::doTick()
{
    assert(m_tickMeasureTs > 0);
    m_tickMeasureTs = 0;

    assert(m_client);
    if (!m_client) {
        return;
    }

    ::cc_mqtt311_client_tick(m_client.get(), m_tickMs);
}

void Mqtt311ClientFilter::socketConnected()
{
    if (2 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): socket connected report" << std::endl;
    }
        
    auto config = CC_Mqtt311ConnectConfig();
    ::cc_mqtt311_client_connect_init_config(&config);

    auto clientId = m_config.m_clientId.toStdString();
    auto username = m_config.m_username.toStdString();
    auto password = parsePassword(m_config.m_password);
    
    if (!clientId.empty()) {
        config.m_clientId = clientId.c_str();
    }

    config.m_username = username.c_str();
    config.m_password = password.data();
    config.m_passwordLen = static_cast<decltype(config.m_passwordLen)>(password.size());
    config.m_keepAlive = m_config.m_keepAlive;
    config.m_cleanSession = 
        (m_config.m_forcedCleanSession) ||
        (clientId.empty()) || 
        (clientId != m_prevClientId) ||
        (m_firstConnect);

    auto ec = 
        cc_mqtt311_client_connect(
            m_client.get(), 
            &config, 
            nullptr, 
            &Mqtt311ClientFilter::connectCompleteCb, 
            this);

    if (ec != CC_Mqtt311ErrorCode_Success) {
        reportError(tr("Failed to initiate MQTT v3.1.1 connection"));
        return;
    }    

    m_prevClientId = clientId;
}

void Mqtt311ClientFilter::socketDisconnected()
{
    if (2 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): socket disconnected report" << std::endl;
    }

    ::cc_mqtt311_client_notify_network_disconnected(m_client.get());
}

void Mqtt311ClientFilter::sendPendingData()
{
    for (auto& dataPtr : m_pendingData) {
        sendDataImpl(std::move(dataPtr));
    }
    m_pendingData.clear();
}

void Mqtt311ClientFilter::sendDataInternal(const unsigned char* buf, unsigned bufLen)
{
    if (3 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): sending " << bufLen << " bytes" << std::endl;
    }

    auto dataInfo = cc_tools_qt::makeDataInfoTimed();
    dataInfo->m_data.assign(buf, buf + bufLen);
    if (!m_sendDataPtr) {
        reportDataToSend(std::move(dataInfo));
        return;
    }

    dataInfo->m_extraProperties = m_sendDataPtr->m_extraProperties;
    m_sendData.append(std::move(dataInfo));
}

void Mqtt311ClientFilter::brokerDisconnectedInternal()
{
    static const QString BrokerDisconnecteError = 
        tr("MQTT311 Broker is disconnected");

    reportError(BrokerDisconnecteError);
}

void Mqtt311ClientFilter::messageReceivedInternal(const CC_Mqtt311MessageInfo& info)
{
    if (2 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): app message received: " << info.m_topic << std::endl;
    }

    assert(m_recvDataPtr);
    auto dataInfo = cc_tools_qt::makeDataInfoTimed();
    if (info.m_dataLen > 0U) {
        dataInfo->m_data.assign(info.m_data, info.m_data + info.m_dataLen);
    }
    auto& props = dataInfo->m_extraProperties;
    props = m_recvDataPtr->m_extraProperties;
    assert(info.m_topic != nullptr);
    props[topicProp()] = info.m_topic;
    props[qosProp()] = static_cast<int>(info.m_qos);
    props[retainedProp()] = info.m_retained;
    m_recvData.append(std::move(dataInfo));
}

void Mqtt311ClientFilter::nextTickProgramInternal(unsigned ms)
{
    if (3 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): tick request: " << ms << std::endl;
    }

    assert(!m_timer.isActive());
    m_tickMs = ms;
    m_tickMeasureTs = QDateTime::currentMSecsSinceEpoch();
    m_timer.start(static_cast<int>(ms));
}

unsigned Mqtt311ClientFilter::cancelTickProgramInternal()
{
    assert(m_tickMeasureTs > 0);
    assert(m_timer.isActive());
    m_timer.stop();
    auto now = QDateTime::currentMSecsSinceEpoch();
    assert(m_tickMeasureTs <= now);
    auto diff = now - m_tickMeasureTs;
    assert(diff < std::numeric_limits<unsigned>::max());
    m_tickMeasureTs = 0U;

    if (3 <= getDebugOutputLevel()) {
        std::cout << '[' << currTimestamp() << "] (" << debugNameImpl() << "): cancel tick: " << diff << std::endl;
    }
        
    return static_cast<unsigned>(diff);
}

void Mqtt311ClientFilter::connectCompleteInternal(CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311ConnectResponse* response)
{
    if (status != CC_Mqtt311AsyncOpStatus_Complete) {
        reportError(tr("Failed to connect to MQTT311 broker with status: ") + statusStr(status));
        return;
    }

    assert(response != nullptr);
    if (response->m_returnCode != CC_Mqtt311ConnectReturnCode_Accepted) {
        reportError(tr("MQTT broker rejected connection with returnCode=") + QString::number(response->m_returnCode));
        return;        
    }

    m_firstConnect = false;

    sendPendingData();

    if (response->m_sessionPresent) {
        return;
    }

    if (m_config.m_subscribes.empty()) {
        return;
    }

    CC_Mqtt311SubscribeHandle subscribe = ::cc_mqtt311_client_subscribe_prepare(m_client.get(), nullptr);
    if (subscribe == nullptr) {
        reportError(tr("Failed to allocate SUBSCRIBE message in MQTT311 client"));
        return;
    }    

    for (auto& sub : m_config.m_subscribes) {
        auto topicStr = sub.m_topic.trimmed().toStdString();

        auto topicConfig = CC_Mqtt311SubscribeTopicConfig();
        ::cc_mqtt311_client_subscribe_init_config_topic(&topicConfig);
        topicConfig.m_topic = topicStr.c_str();
        topicConfig.m_maxQos = static_cast<decltype(topicConfig.m_maxQos)>(sub.m_maxQos);

        auto ec = ::cc_mqtt311_client_subscribe_config_topic(subscribe, &topicConfig);
        if (ec != CC_Mqtt311ErrorCode_Success) {
            reportError(
                QString("%1 \"%2\", ec=%3").arg(tr("Failed to configure topic")).arg(sub.m_topic).arg(ec));
            continue;
        }  
    }

    auto ec = cc_mqtt311_client_subscribe_send(subscribe, &Mqtt311ClientFilter::subscribeCompleteCb, this);
    if (ec != CC_Mqtt311ErrorCode_Success) {
        reportError(tr("Failed to send MQTT311 SUBSCRIBE message"));
        return;
    }    
}

void Mqtt311ClientFilter::subscribeCompleteInternal([[maybe_unused]] CC_Mqtt311SubscribeHandle handle, CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311SubscribeResponse* response)
{
    if (status != CC_Mqtt311AsyncOpStatus_Complete) {
        reportError(tr("Failed to subsribe to MQTT311 topics with status: ") + statusStr(status));
        return;
    }  

    assert (response != nullptr);
    for (auto idx = 0U; idx < response->m_returnCodesCount; ++idx) {
        if (response->m_returnCodes[idx] <= CC_Mqtt311SubscribeReturnCode_SuccessQos2) {
            continue;
        }

        reportError(tr("MQTT broker rejected subscribe with returnCode=") + QString::number(response->m_returnCodes[idx]));
    }       
}

void Mqtt311ClientFilter::publishCompleteInternal([[maybe_unused]] CC_Mqtt311PublishHandle handle, CC_Mqtt311AsyncOpStatus status)
{
    if (status != CC_Mqtt311AsyncOpStatus_Complete) {
        reportError(tr("Failed to publish to MQTT311 broker with status: ") + statusStr(status));
        return;
    }
}

void Mqtt311ClientFilter::sendDataCb(void* data, const unsigned char* buf, unsigned bufLen)
{
    asThis(data)->sendDataInternal(buf, bufLen);
}

void Mqtt311ClientFilter::brokerDisconnectedCb(void* data, [[maybe_unused]] CC_Mqtt311BrokerDisconnectReason reason)
{
    asThis(data)->brokerDisconnectedInternal();
}

void Mqtt311ClientFilter::messageReceivedCb(void* data, const CC_Mqtt311MessageInfo* info)
{
    assert(info != nullptr);
    if (info == nullptr) {
        return;
    }

    asThis(data)->messageReceivedInternal(*info);
}

void Mqtt311ClientFilter::nextTickProgramCb(void* data, unsigned ms)
{
    asThis(data)->nextTickProgramInternal(ms);
}

unsigned Mqtt311ClientFilter::cancelTickProgramCb(void* data)
{
    return asThis(data)->cancelTickProgramInternal();
}

void Mqtt311ClientFilter::errorLogCb([[maybe_unused]] void* data, const char* msg)
{
    auto timestamp = std::chrono::high_resolution_clock::now();
    auto sinceEpoch = timestamp.time_since_epoch();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(sinceEpoch).count();
    std::cerr << '[' << milliseconds << "] MQTT ERROR: " << msg << std::endl;
}

void Mqtt311ClientFilter::connectCompleteCb(void* data, CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311ConnectResponse* response)
{
    asThis(data)->connectCompleteInternal(status, response);
}

void Mqtt311ClientFilter::subscribeCompleteCb(void* data, CC_Mqtt311SubscribeHandle handle, CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311SubscribeResponse* response)
{
    asThis(data)->subscribeCompleteInternal(handle, status, response);
}

void Mqtt311ClientFilter::publishCompleteCb(void* data, CC_Mqtt311PublishHandle handle, CC_Mqtt311AsyncOpStatus status)
{
    asThis(data)->publishCompleteInternal(handle, status);
}

}  // namespace cc_plugin_mqtt311_client_filter


