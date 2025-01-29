#pragma once

#include <string>
#include <memory>

#include "IntellBoxCommon/Utils/TcpServer/TcpServerObserverInterface.h"

namespace intellBoxSDK {

class TcpServerInterface {
public:
    virtual ~TcpServerInterface() = default;

    /**
     * Returns whether this client is currently connected to TcpServer.
     * 
     * @param clientIP 
     * @return if the client is connected 
     */
    virtual bool isClientConnected(const std::string& clientIP) = 0;

    /**
     * @brief start the server
     * @return =0 success, <0 failure
     */
    virtual int start() = 0;

    /**
     * @brief Send the data to client
     * 
     * @param clientIP 
     * @return >0 the send size, <0 failure
     */
    virtual int sendData(const std::string& clientIP, const uint8_t* buffer, uint32_t bufferSize) = 0;

    /**
     * @brief Disconnect client
     * 
     * @param clientIP 
     */
    virtual void disconnectClient(const std::string& clientIP) = 0;

    /**
     * @brief add the TcpServer Observer
     * 
     * @param ob 
     */
    virtual void addTcpServerObserver(std::shared_ptr<TcpServerObserverInterface> ob) = 0;

    /**
     * @brief remove the TcpServer Observer
     * 
     * @param ob 
     */
    virtual void removeTcpServerObserver(std::shared_ptr<TcpServerObserverInterface> ob) = 0;
};

}  // namespace intellBoxSDK
