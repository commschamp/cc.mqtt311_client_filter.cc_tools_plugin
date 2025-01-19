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

#include <cc_tools_qt/ToolsFilter.h>
#include <cc_tools_qt/version.h>

#include <cc_mqtt311_client/client.h>

#include <QtCore/QByteArray>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QTimer>

#include <list>
#include <memory>
#include <string>

static_assert(CC_MQTT311_CLIENT_MAKE_VERSION(1, 0, 4) <= CC_MQTT311_CLIENT_VERSION, "The version of the cc_mqtt311_client library is too old");
static_assert(CC_TOOLS_QT_MAKE_VERSION(6, 0, 0) <= CC_TOOLS_QT_VERSION, "The version of the cc_tools_qt library is too old");

namespace cc_plugin_mqtt311_client_filter
{

class Mqtt311ClientFilter final : public cc_tools_qt::ToolsFilter
{
    Q_OBJECT

public:
    struct SubConfig
    {
        QString m_topic;
        int m_maxQos = 2;
    };

    // erase the element mustn't invalidate references to other elements, using list.
    using SubConfigsList = std::list<SubConfig>; 

    struct Config
    {
        unsigned m_respTimeout = 0U;
        QString m_clientId;
        QString m_username; 
        QString m_password; 
        QString m_pubTopic;
        int m_pubQos = 0;
        SubConfigsList m_subscribes;
        unsigned m_keepAlive = 60;
        bool m_forcedCleanSession = false;
    };

    Mqtt311ClientFilter();
    ~Mqtt311ClientFilter() noexcept;

    Config& config()
    {
        return m_config;
    }

    void forceCleanSession()
    {
        m_firstConnect = true;
    }

signals:
    void sigConfigChanged();    

protected:
    virtual bool startImpl() override;
    virtual void stopImpl() override;
    virtual QList<cc_tools_qt::ToolsDataInfoPtr> recvDataImpl(cc_tools_qt::ToolsDataInfoPtr dataPtr) override;
    virtual QList<cc_tools_qt::ToolsDataInfoPtr> sendDataImpl(cc_tools_qt::ToolsDataInfoPtr dataPtr) override;
    virtual void socketConnectionReportImpl(bool connected) override;
    virtual void applyInterPluginConfigImpl(const QVariantMap& props) override;     
    virtual const char* debugNameImpl() const override;

private slots:
    void doTick();

private:
    struct ClientDeleter
    {
        void operator()(CC_Mqtt311Client* ptr)
        {
            ::cc_mqtt311_client_free(ptr);
        }
    };
    
    using ClientPtr = std::unique_ptr<CC_Mqtt311Client, ClientDeleter>;

    void socketConnected();
    void socketDisconnected();
    void sendPendingData();

    void sendDataInternal(const unsigned char* buf, unsigned bufLen);
    void brokerDisconnectedInternal();
    void messageReceivedInternal(const CC_Mqtt311MessageInfo& info);
    void nextTickProgramInternal(unsigned ms);
    unsigned cancelTickProgramInternal();
    void connectCompleteInternal(CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311ConnectResponse* response);
    void subscribeCompleteInternal(CC_Mqtt311SubscribeHandle handle, CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311SubscribeResponse* response);
    void publishCompleteInternal(CC_Mqtt311PublishHandle handle, CC_Mqtt311AsyncOpStatus status);
    

    static void sendDataCb(void* data, const unsigned char* buf, unsigned bufLen);
    static void brokerDisconnectedCb(void* data, CC_Mqtt311BrokerDisconnectReason reason);
    static void messageReceivedCb(void* data, const CC_Mqtt311MessageInfo* info);
    static void nextTickProgramCb(void* data, unsigned ms);
    static unsigned cancelTickProgramCb(void* data);
    static void errorLogCb(void* data, const char* msg);
    static void connectCompleteCb(void* data, CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311ConnectResponse* response);
    static void subscribeCompleteCb(void* data, CC_Mqtt311SubscribeHandle handle, CC_Mqtt311AsyncOpStatus status, const CC_Mqtt311SubscribeResponse* response);
    static void publishCompleteCb(void* data, CC_Mqtt311PublishHandle handle, CC_Mqtt311AsyncOpStatus status);

    ClientPtr m_client;
    QTimer m_timer;
    std::list<cc_tools_qt::ToolsDataInfoPtr> m_pendingData;
    cc_tools_qt::ToolsDataInfo::DataSeq m_inData;
    Config m_config;
    std::string m_prevClientId;
    unsigned m_tickMs = 0U;
    qint64 m_tickMeasureTs = 0;
    cc_tools_qt::ToolsDataInfoPtr m_recvDataPtr;
    QList<cc_tools_qt::ToolsDataInfoPtr> m_recvData;
    cc_tools_qt::ToolsDataInfoPtr m_sendDataPtr;
    QList<cc_tools_qt::ToolsDataInfoPtr> m_sendData;
    bool m_firstConnect = true;
    bool m_socketConnected = false;
};

using Mqtt311ClientFilterPtr = std::shared_ptr<Mqtt311ClientFilter>;

inline
Mqtt311ClientFilterPtr makeMqtt311ClientFilter()
{
    return Mqtt311ClientFilterPtr(new Mqtt311ClientFilter());
}

}  // namespace cc_plugin_mqtt311_client_filter


