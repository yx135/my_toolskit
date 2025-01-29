#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

#include <unistd.h>

#include <thread>

#include "IntellBoxCommon/SDKInterfaces/Common.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/Utils/TcpServer/TcpServer.h"

namespace intellBoxSDK {

std::shared_ptr<TcpServerInterface> TcpServer::create(const std::string& serverIP, uint16_t portNum) {
    auto tcpServer = std::shared_ptr<TcpServer>(new TcpServer());
    if (tcpServer) {
        if (0 == tcpServer->initialize(serverIP, portNum)) {
            return tcpServer;
        }
    }

    return nullptr;
}

bool TcpServer::isClientConnected(const std::string& clientIP) {
    std::unique_lock<std::mutex> lock(m_clientsMutex);
    return m_clients.count(clientIP) > 0;
}

int TcpServer::start() {
    if (listen(m_sockFd, 20) < 0) {
        close(m_sockFd);
        LOG_ERROR("[TcpServer:{0}]listen failed", __LINE__);
        return -1;
    }

    m_loopThread = std::thread([this]() {
        ev::dynamic_loop loop;
        ev::io servIO;
        servIO.set(loop);
        servIO.set<TcpServer, &TcpServer::acceptCallback>(this);
        servIO.start(m_sockFd, ev::READ);
        loop.run(0);
    });
    m_loopThread.detach();

    return 0;
}

int TcpServer::sendData(const std::string& clientIP, const uint8_t* buffer, uint32_t bufferSize) {
    uint32_t sendSize = 0;
    while (sendSize < bufferSize) {
        if (0 != m_clients.count(clientIP)) {
            if (m_clients[clientIP]) {
                auto ret = send(m_clients[clientIP]->fd, buffer + sendSize, bufferSize - sendSize, 0);
                if (ret < 0) {
                    LOG_INFO("[TcpServer:{0}]send failed:{1}", __LINE__, errno);
                    if (EAGAIN == errno) {
                        continue;
                    } else {
                        disconnectClient(clientIP);
                        return ret;
                    }
                } else {
                    sendSize += ret;
                }
            } else {
                return -1;
            }
        } else {
            return -1;
        }
    }

    return sendSize;
}

void TcpServer::disconnectClient(const std::string& clientIP) {
    LOG_INFO("[TcpServer:{0}]disconnect:{1}", __LINE__, clientIP);
    std::shared_ptr<ev::io> watcher = nullptr;
    {
        std::unique_lock<std::mutex> lock(m_clientsMutex);
        auto it = m_clients.find(clientIP);
        if (it != m_clients.end()) {
            watcher = it->second;
            m_clients.erase(it);
        }
    }

    if (watcher) {
        watcher->stop();
        close(watcher->fd);
    }

    notifyClientDisconnected(clientIP);

    return;
}

void TcpServer::addTcpServerObserver(std::shared_ptr<TcpServerObserverInterface> ob) {
    {
        std::unique_lock<std::mutex> lock(m_tcpServerObserversMutex);
        m_tcpServerObservers.insert(ob);
    }

    for (auto client : m_clients) {
        notifyClientConnected(client.first);
    }
}

void TcpServer::removeTcpServerObserver(std::shared_ptr<TcpServerObserverInterface> ob) {
    std::unique_lock<std::mutex> lock(m_tcpServerObserversMutex);
    m_tcpServerObservers.erase(ob);
}

void TcpServer::acceptCallback(ev::io& watcher, int revents) {
    LOG_TRACE("[TcpServer:{0}]acceptCallback", __LINE__);
    if (EV_ERROR & revents) {
        LOG_ERROR("[TcpServer:{0}]accecpt error", __LINE__);
        return;
    }

    struct sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);

    int clientFd = accept4(watcher.fd, (struct sockaddr*)(&clientAddr), &clientLen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (clientFd < 0) {
        LOG_ERROR("[TcpServer:{0}]accept fail", __LINE__);
        return;
    }

    std::string clientIP = inet_ntoa(clientAddr.sin_addr);

    LOG_INFO("[TcpServer:{0}]client:{1}", __LINE__, clientIP);

    /// if client exist, remove the watcher, reset previous client
    auto preWatcher = getClientWatcher(clientIP);
    if (preWatcher) {
        preWatcher->stop();
        close(preWatcher->fd);
        removeClient(clientIP);
    }

    int one = 1;
    setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    auto readIO = std::make_shared<ev::io>();
    if (readIO) {
        readIO->set(watcher.loop);
        readIO->set<TcpServer, &TcpServer::readCallback>(this);
        readIO->start(clientFd, ev::READ);

        addClient(clientIP, readIO);
        notifyClientConnected(clientIP);
    } else {
        close(clientFd);
    }

    return;
}

void TcpServer::readCallback(ev::io& watcher, int revents) {
    UNUSED_VAR(revents);
    std::string clientIP = getClientIP(watcher.fd);
    if (clientIP.empty()) {
        watcher.stop();
        close(watcher.fd);
    }

    uint8_t readBuf[512] = {0};
    int readLen = recv(watcher.fd, readBuf, sizeof(readBuf), 0);
    LOG_TRACE("[TcpServer:{0}]get data from:{1}, length:{2}", __LINE__, clientIP, readLen);
    if (readLen < 0) {
        LOG_ERROR("[TcpServer:{0}]recv error, clientIP:{1},readLen:{2}, errno:{3}", __LINE__, clientIP, readLen, errno);
        if (EAGAIN == errno || EWOULDBLOCK == errno) {
            return;
        } else {
            watcher.stop();
            close(watcher.fd);
            removeClient(clientIP);

            notifyClientDisconnected(clientIP);
            return;
        }
    } else if (0 == readLen) {
        watcher.stop();
        close(watcher.fd);
        removeClient(clientIP);

        notifyClientDisconnected(clientIP);
        return;
    }

    notifyClientDataRecv(clientIP, readBuf, readLen);
}

int TcpServer::initialize(const std::string& serverIP, uint16_t portNum) {
    m_sockFd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (m_sockFd < 0) {
        LOG_ERROR("[TcpServer:{0}]initialize tcpserver failed", __LINE__);
        return -1;
    }

    int opt = 1;
    setsockopt(m_sockFd, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt, sizeof(opt));

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    // serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(portNum);

    if (!inet_aton(serverIP.c_str(), &serverAddr.sin_addr)) {
        LOG_ERROR("[TcpServer:{0}]bad server ip address", __LINE__);
        return -1;
    }

    if (bind(m_sockFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(m_sockFd);
        LOG_ERROR("[TcpServer:{0}]bind failed, ip:{1}", __LINE__, serverIP);
        return -1;
    }

    return 0;
}

std::shared_ptr<ev::io> TcpServer::getClientWatcher(const std::string& clientIP) {
    std::unique_lock<std::mutex> m_clientsMutex;
    if (m_clients.count(clientIP)) {
        return m_clients[clientIP];
    } else {
        return nullptr;
    }
}

std::string TcpServer::getClientIP(int fd) {
    std::unique_lock<std::mutex> m_clientsMutex;
    for (auto client : m_clients) {
        if (fd == client.second->fd) {
            return client.first;
        }
    }

    std::string clientIP;
    return clientIP;
}

void TcpServer::addClient(const std::string& ipAddr, std::shared_ptr<ev::io> watcher) {
    std::unique_lock<std::mutex> m_clientsMutex;
    if (m_clients.count(ipAddr)) {
        m_clients[ipAddr] = watcher;
    } else {
        m_clients.insert(std::make_pair(ipAddr, watcher));
    }

    return;
}

void TcpServer::removeClient(const std::string& ipAddr) {
    std::unique_lock<std::mutex> m_clientsMutex;
    m_clients.erase(ipAddr);
}

void TcpServer::notifyClientDataRecv(const std::string& clientIP, uint8_t* buffer, uint32_t bufferSize) {
    std::unique_lock<std::mutex> lock(m_tcpServerObserversMutex);
    for (auto ob : m_tcpServerObservers) {
        ob->onClientDataRecv(clientIP, buffer, bufferSize);
    }

    return;
}

void TcpServer::notifyClientConnected(const std::string& clientIP) {
    std::unique_lock<std::mutex> lock(m_tcpServerObserversMutex);
    for (auto ob : m_tcpServerObservers) {
        ob->onClientConnected(clientIP);
    }

    return;
}

void TcpServer::notifyClientDisconnected(const std::string& clientIP) {
    std::unique_lock<std::mutex> lock(m_tcpServerObserversMutex);
    for (auto ob : m_tcpServerObservers) {
        ob->onClientDisconnected(clientIP);
    }

    return;
}

}  // namespace intellBoxSDK
