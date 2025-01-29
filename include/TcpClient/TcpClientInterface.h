#pragma once

#include <string>
#include <memory>
#include <chrono>
#include "IntellBoxCommon/Utils/TcpClient/TcpClientObserverInterface.h"

namespace intellBoxSDK {

class TcpClientInterface {
public:
    virtual ~TcpClientInterface() = default;

    /**
     * Returns whether this client is connected.
     *
     * @return if the client is connected
     */
    virtual bool isConnected() = 0;

    /**
     * @brief Send the data to server
     *
     * @return >0 the send size, <0 failure
     */
    virtual int sendData(const void* buffer, uint32_t bufferSize, const std::chrono::seconds& timeout) = 0;

    /**
     * @brief Set the connected Server
     *
     * @param serverIp
     * @param serverPort
     */
    virtual void setServer(const std::string& serverIp, uint16_t serverPort) = 0;

    /**
     * @brief Get the connected Server
     *
     * @param serverIp
     * @param serverPort
     */
    virtual void getServer(std::string& serverIp, uint16_t& serverPort) = 0;

    /**
     * @brief Disconnect client
     *
     * @param clientIP
     */
    virtual void disconnect() = 0;

    /**
     * @brief add the TcpClient Observer
     *
     * @param ob
     */
    virtual void addTcpClientObserver(std::shared_ptr<TcpClientObserverInterface> ob) = 0;

    /**
     * @brief remove the TcpClient Observer
     *
     * @param ob
     */
    virtual void removeTcpClientObserver(std::shared_ptr<TcpClientObserverInterface> ob) = 0;
};

}  // namespace intellBoxSDK
