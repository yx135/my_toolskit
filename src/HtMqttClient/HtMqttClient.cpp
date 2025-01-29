
#include "MQTTClient.h"

#include "IntellBoxCommon/SDKInterfaces/Common.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/Utils/HtMqttClient/HtMqttClient.h"

namespace intellBoxSDK {

void delivered(void* context, MQTTClient_deliveryToken dt) {
}

int msgarrvd(void* context, char* topicName, int topicLen, MQTTClient_message* message) {
    LOG_INFO("[HtMqttClient:{0}]msgarrvd", __LINE__);

    HtMqttClient* client = reinterpret_cast<HtMqttClient*>(context);
    client->notifyMessageRecv(topicName, std::string(reinterpret_cast<char*>(message->payload), message->payloadlen));

    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

void connlost(void* context, char* cause) {
    try {
        LOG_INFO("[HtMqttClient:{0}]connlost", __LINE__);
        if (cause) {
            LOG_INFO("[HtMqttClient:{0}]cause:{1}", __LINE__, std::string(cause));
        }
        HtMqttClient* client = reinterpret_cast<HtMqttClient*>(context);
        {
            std::unique_lock<std::mutex> lock(client->m_connectMutex);
            client->m_isConnected = false;
            client->m_connectCV.notify_all();
        }
    } catch (...) {
    }
}

HtMqttClient::~HtMqttClient() {
    m_quitFlag = true;
    if (m_handle) {
        MQTTClient_destroy(&m_handle);
        m_handle = nullptr;
    }

    if (m_uris) {
        free(m_uris[0]);
        m_uris = nullptr;
    }
}

std::shared_ptr<HtMqttClient> HtMqttClient::create(
    const std::string& serverUri,
    const std::string& clientId,
    const std::string& userName,
    const std::string& passwd,
    SSLInfo& sslInfo) {
    auto client = std::shared_ptr<HtMqttClient>(new HtMqttClient(serverUri, clientId, userName, passwd, sslInfo));
    if (client) {
        if (0 == client->initialize()) {
            return client;
        }
    }

    return nullptr;
}

int HtMqttClient::setServer(const std::string& uri) {
    if (m_serverUri != uri) {
        auto preUri = m_serverUri;
        m_serverUri = uri;
        m_uris[0] = const_cast<char*>(m_serverUri.c_str());
        if (isConnected()) {
            auto ret = MQTTClient_disconnect(m_handle, 0);
            if (MQTTCLIENT_SUCCESS == ret) {
                {
                    std::unique_lock<std::mutex> lock(m_connectMutex);
                    m_isConnected = false;
                    m_connectCV.notify_all();
                }
                notifyDisconnected(preUri);
            }
        }
    }

    return 0;
}

const std::string& HtMqttClient::getServer() const {
    return m_serverUri;
}

int HtMqttClient::setUser(const std::string& userName, const std::string& passwd) {
    if (m_userName != userName || m_passwd != passwd) {
        m_userName = userName;
        m_passwd = passwd;
        if (isConnected()) {
            auto ret = MQTTClient_disconnect(m_handle, 0);
            if (MQTTCLIENT_SUCCESS == ret) {
                notifyDisconnected(m_serverUri);
            }
        }
    }

    return 0;
}

const std::string& HtMqttClient::getUserName() const {
    return m_userName;
}

int HtMqttClient::disconnect() {
    LOG_INFO("[HtMqttClient:{0}]disconnect", __LINE__);

    int ret = 0;
    if (isConnected()) {
        ret = MQTTClient_disconnect(m_handle, 0);
        if (MQTTCLIENT_SUCCESS == ret) {
            {
                std::unique_lock<std::mutex> lock(m_connectMutex);
                m_isConnected = false;
                m_connectCV.notify_all();
            }
            notifyDisconnected(m_serverUri);
        }
    }

    return ret;
}

bool HtMqttClient::isConnected() {
    bool bConnectStatus = static_cast<bool>(MQTTClient_isConnected(m_handle));
    {
        std::unique_lock<std::mutex> lock(m_connectMutex);
        m_isConnected = bConnectStatus;
        m_connectCV.notify_all();
    }
    return bConnectStatus;
}

int HtMqttClient::publishMessage(const std::string& topic, const std::string& payload, int qos, bool isRetained) {
    int waitTime = 5000;  /// the unit is milliseconds

    LOG_INFO(
        "[HtMqttClient:{0}]MQTTClient_publishMessage, qos:{1}, topic:{2}, payload:{3}", __LINE__, qos, topic, payload);
    if (!isConnected()) {
        LOG_INFO("[HtMqttClient:{0}]mqtt is not connected.", __LINE__);
        return -1;
    }

    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    pubmsg.payload = const_cast<char*>(payload.c_str());
    pubmsg.payloadlen = payload.size();
    pubmsg.qos = qos;
    pubmsg.retained = isRetained;
    auto ret = MQTTClient_publishMessage(m_handle, topic.c_str(), &pubmsg, &token);
    if (MQTTCLIENT_SUCCESS != ret) {
        LOG_INFO("[HtMqttClient:{0}]MQTTClient_publishMessage failed:{1}", __LINE__, ret);
        if (isConnected()) {
            MQTTClient_disconnect(m_handle, 0);
        }
        return ret;
    }

    LOG_INFO("[HtMqttClient:{0}]MQTTClient_publishMessage, dt:{1}", __LINE__, token);
    ret = MQTTClient_waitForCompletion(m_handle, token, waitTime);
    if (MQTTCLIENT_SUCCESS != ret) {
        LOG_INFO("[HtMqttClient:{0}]MQTTClient_waitForCompletion failed:{1}", __LINE__, ret);
        // goto error;
    }
    // error:
    //    if (MQTTCLIENT_SUCCESS != ret) {
    //        if (isConnected()) {
    //            MQTTClient_disconnect(m_handle, 0);
    //        }
    //    }

    LOG_INFO("[HtMqttClient:{0}]MQTTClient_publishMessage, ret:{1}", __LINE__, ret);

    return ret;
}

int HtMqttClient::subscribeMessage(const std::string& topic, int qos) {
    m_subscribeTopics[topic] = qos;
    if (isConnected()) {
        MQTTClient_subscribe(m_handle, topic.c_str(), qos);
    }

    return 0;
}

void HtMqttClient::addHtMqttClientObserver(std::shared_ptr<HtMqttClientObserverInterface> ob) {
    if (ob) {
        std::unique_lock<std::mutex> lock(m_obsMutex);
        m_obs.insert(ob);
    }

    if (MQTTClient_isConnected(m_handle)) {
        ob->onMqttClientConnected(m_serverUri);
    }
}

void HtMqttClient::removeHtMqttClientObserver(std::shared_ptr<HtMqttClientObserverInterface> ob) {
    if (ob) {
        std::unique_lock<std::mutex> lock(m_obsMutex);
        m_obs.erase(ob);
    }
}

void HtMqttClient::notifyMessageRecv(const std::string& topic, const std::string& payload) {
    LOG_INFO("[HtMqttClient:{0}]notifyMessageRecv topic:{1}, payload:{2}", __LINE__, topic, payload);
    std::unique_lock<std::mutex> lock(m_obsMutex);
    for (auto ob : m_obs) {
        ob->onMqttClientMessageRecv(topic, payload);
    }
}

void HtMqttClient::notifyConnected(const std::string& serverUri) {
    LOG_INFO("[HtMqttClient:{0}]notifyConnected serverUri:{1}", __LINE__, serverUri);
    for (auto& ele : m_subscribeTopics) {
        MQTTClient_subscribe(m_handle, ele.first.c_str(), ele.second);
    }

    {
        std::unique_lock<std::mutex> lock(m_obsMutex);
        for (auto ob : m_obs) {
            ob->onMqttClientConnected(serverUri);
        }
    }
}

void HtMqttClient::notifyDisconnected(const std::string& serverUri) {
    LOG_INFO("[HtMqttClient:{0}]notifyDisconnected serverUri:{1}", __LINE__, serverUri);
    std::unique_lock<std::mutex> lock(m_obsMutex);
    for (auto ob : m_obs) {
        ob->onMqttClientDisconnected(serverUri);
    }
}

HtMqttClient::HtMqttClient(
    const std::string& serverUri,
    const std::string& clientId,
    const std::string& userName,
    const std::string& passwd,
    SSLInfo& sslInfo) :
        m_quitFlag(false), m_serverUri(serverUri), m_clientId(clientId), m_userName(userName), m_passwd(passwd), m_sslInfo(sslInfo) {
}

int HtMqttClient::initialize() {
    m_isConnected = false;
    m_uris = (char**)malloc(1 * sizeof(char*));
    if (m_uris == nullptr) {
        LOG_INFO("[HtMqttClient:{0}]malloc failed", __LINE__);
        return -1;
    }

    m_uris[0] = const_cast<char*>(m_serverUri.c_str());
    auto ret = MQTTClient_create(&m_handle, m_serverUri.c_str(), m_clientId.c_str(), MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (MQTTCLIENT_SUCCESS != ret) {
        LOG_INFO("[HtMqttClient:{0}]MQTTClient_create failed:{1}", __LINE__, ret);
        return ret;
    }

    ret = MQTTClient_setCallbacks(m_handle, this, connlost, msgarrvd, delivered);
    if (MQTTCLIENT_SUCCESS != ret) {
        LOG_INFO("[HtMqttClient:{0}]MQTTClient_setCallbacks failed:{1}", __LINE__, ret);
        return ret;
    }

    m_connectThread = std::thread(std::bind(&HtMqttClient::connectThreadFunc, this));
    m_connectThread.detach();

    return ret;
}

void HtMqttClient::connectThreadFunc() {
    auto connectInterval = std::chrono::seconds(5);
    int connectTimeout = 2;      /// the unit is second
    int keepAliveInterval = 30;  /// the unit is second
    while (!m_quitFlag) {
        while (true) {
            std::unique_lock<std::mutex> lock(m_connectMutex);
            if (!m_isConnected || m_quitFlag) {
                break;
            }
            m_connectCV.wait_for(
                lock, std::chrono::seconds(5), [this]() -> bool { return !m_isConnected || m_quitFlag; });
        }

        LOG_INFO(
            "[HtMqttClient:{0}]connectThreadFunc, MQTTClient_isConnected:{1}, m_quitFlag:{2}",
            __LINE__,
            m_isConnected,
            m_quitFlag);

        if (m_quitFlag) {
            break;
        }
        std::this_thread::sleep_for(connectInterval);
        if (!MQTTClient_isConnected(m_handle)) {
            MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
            conn_opts.keepAliveInterval = keepAliveInterval;
            conn_opts.connectTimeout = connectTimeout;
            conn_opts.username = m_userName.c_str();
            conn_opts.password = m_passwd.c_str();
            conn_opts.cleansession = 1;
            conn_opts.serverURIcount = 1;
            conn_opts.serverURIs = m_uris;
            LOG_INFO(
                "[HtMqttClient:{0}]connectThreadFunc, clientId:{1},username:{2}, passwd:{3}, uri:{4}",
                __LINE__,
                m_clientId,
                m_userName,
                m_passwd,
                m_serverUri);
            if(!m_sslInfo.trustStore.empty()){
                MQTTClient_SSLOptions sslopts = MQTTClient_SSLOptions_initializer;
                sslopts.trustStore = m_sslInfo.trustStore.c_str();
                sslopts.enableServerCertAuth = m_sslInfo.enableServerCertAuth;
                conn_opts.ssl = &sslopts;
            }
            int ret = MQTTClient_connect(m_handle, &conn_opts);
            if (MQTTCLIENT_SUCCESS == ret) {
                m_isConnected = true;
                notifyConnected(m_serverUri);
            } else {
                m_isConnected = false;
                notifyDisconnected(m_serverUri);
            }
        }
    }
}

}  // namespace intellBoxSDK
