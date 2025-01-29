#ifndef HTMQTTCLIENTOBSERVERINTERFACE_H
#define HTMQTTCLIENTOBSERVERINTERFACE_H

#include "IntellBoxCommon/SDKInterfaces/Common.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/SDKInterfaces/Error.h"
#include <string>

class HtMqttClientObserverInterface {
public:
    virtual ~HtMqttClientObserverInterface() = default;

    /**
     * @brief notify the connected event when connect
     *
     * @param serverURI
     */
    virtual void onMqttClientConnected(const std::string& serverURI) = 0;

    /**
     * @brief Notify the disconnected event when disconnect
     *
     * @param serverURI
     */
    virtual void onMqttClientDisconnected(const std::string& serverURI) = 0;

    /**
     * @brief Notify the data when data received
     *
     * @param topic
     * @param payload
     */
    virtual void onMqttClientMessageRecv(const std::string& topic, const std::string& payload) = 0;
};
#endif  // HTMQTTCLIENTOBSERVERINTERFACE_H
