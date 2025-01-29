#ifndef HTMQTTCLIENTINTERFACE_H
#define HTMQTTCLIENTINTERFACE_H

#include "IntellBoxCommon/Utils/HtMqttClient/HtMqttClientObserverInterface.h"

namespace intellBoxSDK {
class HtMqttClientInterface {
public:
    virtual ~HtMqttClientInterface() = default;

    virtual int setServer(const std::string& uri) = 0;
    virtual const std::string& getServer() const = 0;
    virtual int setUser(const std::string& userName, const std::string& passwd) = 0;
    virtual const std::string& getUserName() const = 0;
    virtual int disconnect() = 0;
    virtual bool isConnected() = 0;
    virtual int publishMessage(const std::string& topic, const std::string& payload, int qos, bool isRetained) = 0;
    virtual int subscribeMessage(const std::string& topic, int qos) = 0;

    /**
     * @brief add the mqttClient Observer
     *
     * @param ob
     */
    virtual void addHtMqttClientObserver(std::shared_ptr<HtMqttClientObserverInterface> ob) = 0;

    /**
     * @brief remove the mqttClient Observer
     *
     * @param ob
     */
    virtual void removeHtMqttClientObserver(std::shared_ptr<HtMqttClientObserverInterface> ob) = 0;
};

}  // namespace intellBoxSDK

#endif  // HTMQTTCLIENTINTERFACE_H
