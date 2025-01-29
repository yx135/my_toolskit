#ifndef HTMQTTCLIENT_H
#define HTMQTTCLIENT_H

#include <cstdio>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <condition_variable>

#include "IntellBoxCommon/Utils/HtMqttClient/HtMqttClientInterface.h"

namespace intellBoxSDK {
class HtMqttClient : public HtMqttClientInterface {
public:
    struct SSLInfo{
       std::string trustStore;
       bool enableServerCertAuth;
    };

    ~HtMqttClient();
    static std::shared_ptr<HtMqttClient> create(
        const std::string& serverUri,
        const std::string& clientId,
        const std::string& userName,
        const std::string& passwd,
        SSLInfo& sslInfo);

    /// @name DoorManagerInterface Functions
    /// @{
    int setServer(const std::string& uri) override;
    const std::string& getServer() const override;
    int setUser(const std::string& userName, const std::string& passwd) override;
    const std::string& getUserName() const override;
    int disconnect() override;
    bool isConnected() override;
    int publishMessage(const std::string& topic, const std::string& payload, int qos, bool isRetained) override;
    int subscribeMessage(const std::string& topic, int qos) override;
    void addHtMqttClientObserver(std::shared_ptr<HtMqttClientObserverInterface> ob) override;
    void removeHtMqttClientObserver(std::shared_ptr<HtMqttClientObserverInterface> ob) override;
    /// @}

    /// for mqtt callbacks
    void notifyMessageRecv(const std::string& topic, const std::string& payload);
    void notifyConnected(const std::string& serverUri);
    void notifyDisconnected(const std::string& serverUri);

public:
    bool m_isConnected;
    std::mutex m_connectMutex;
    std::condition_variable m_connectCV;

private:
    HtMqttClient(
        const std::string& serverUri,
        const std::string& clientId,
        const std::string& userName,
        const std::string& passwd,
        SSLInfo& sslInfo);
    int initialize();
    void connectThreadFunc();

    bool m_quitFlag;

    std::thread m_connectThread;

    std::string m_serverUri;
    std::string m_clientId;
    std::string m_userName;
    std::string m_passwd;
    SSLInfo m_sslInfo;
    char** m_uris;
    void* m_handle;

    std::unordered_map<std::string, int> m_subscribeTopics;

    mutable std::mutex m_obsMutex;
    std::unordered_set<std::shared_ptr<HtMqttClientObserverInterface>> m_obs;
};

}  // namespace intellBoxSDK

#endif  // HtMqttClient_H
