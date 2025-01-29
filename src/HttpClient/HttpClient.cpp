#include "HttpClient.h"
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include "IntellBoxCommon/Utils/Logger/Logger.h"

#define debug(fmt, ...) //printf(fmt, ##__VA_ARGS__)
namespace intellBoxSDK{

HttpClient::HttpClient(const std::string &host, uint16_t port)
{
    memset(&m_si, 0, sizeof(m_si));
    m_connected = false;
    struct hostent* he = gethostbyname(host.c_str());
    if (he == nullptr)
        return;
    m_host = host;
    m_port = port;
    m_fd = -1;
    m_si.sin_family = AF_INET;
    m_si.sin_addr = *reinterpret_cast<struct in_addr *>(he->h_addr);
    m_si.sin_port = htons(port);
    debug("addr:%08x\n", m_si.sin_addr.s_addr);
}

void HttpClient::disconnectServer()
{
    debug("disconnectServer\n");
    close(m_fd);
    m_connected = false;
    m_fd = -1;
}

Error HttpClient::connectServer()
{
    if (!m_connected)
    {
        if (m_si.sin_port == 0)
            return Error::CONNECTION_FAIL;
        m_fd = socket(AF_INET, SOCK_STREAM, 0);
        unsigned long ul = 1;
        ioctl(m_fd, FIONBIO, &ul);
        int error = 0;
        int len = sizeof(error);
        if (connect(m_fd, reinterpret_cast<sockaddr *>(&m_si), sizeof(sockaddr)) == -1)
        {
            debug("connect suspend...\n");
            timeval tm;
            tm.tv_sec = 2;          // timeout 1s
            tm.tv_usec = 0;
            fd_set set;
            FD_ZERO(&set);
            FD_SET(m_fd, &set);
            if (select(m_fd + 1, NULL, &set, NULL, &tm) > 0)
            {
                debug("connect ok...\n");
                getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            }
            else
            {
                error = 1;
            }
            debug("error=%d\n", error);
        }
        else
        {
            debug("connect directly\n");
        }
        if (error == 0)
        {
            ulong ul = 0;
            ioctl(m_fd, FIONBIO, &ul);
            m_connected = true;
        }
        else
        {
            disconnectServer();
            return Error::CONNECTION_FAIL;
        }
    }
    return Error::SUCCESS;
}

Error HttpClient::sendHtml(const string& action, const string& content)
{
    string html = "POST " + action + " HTTP/1.0\r\n";
    char buf[100];
    sprintf(buf, "HOST: %s:%d\r\n", m_host.c_str(), m_port);
    html += buf;
    html += "User-Agent: CZQ HTTP 0.1\r\nCache-Control: no-cache\r\nContent-Type: application/json\r\ndataType: json\r\nAccept: */*\r\n";
    sprintf(buf, "Content-Length: %u\r\n\r\n", static_cast<unsigned int>(content.length()));
    html += buf;
    html += content;
    debug("[upload]%s\n", html.c_str());
    int len = html.length();
    int sent_len = 0;
    const char* text = html.c_str();
    debug("len=%d\n", len);
    while (sent_len < len)
    {
        int ret = send(m_fd, text + sent_len, len - sent_len, 0);
        if (ret <= 0)
        {
            debug("sent_len = %d\n", sent_len);
            disconnectServer();
            return Error::SEND_FAIL;
        }
        sent_len += ret;
    }
    debug("sent ok\n");
    return Error::SUCCESS;
}

Error HttpClient::getResponse(string& response)
{
    char buf[102400];
    int len = 0;
    fd_set fs_read;
    struct timeval time;
    time.tv_sec = 5;
    time.tv_usec = 0;
    response.clear();
    debug("connected?%d\n", m_connected);
    if (!m_connected)
        return Error::CONNECTION_FAIL;
    for (;;)
    {
        FD_ZERO(&fs_read);
        FD_SET(m_fd, &fs_read);
        if (select(m_fd + 1, &fs_read, NULL, NULL, &time) > 0)
        {
            if (FD_ISSET(m_fd, &fs_read))
            {
                len = recv(m_fd, buf, sizeof(buf), 0);
                if (len <= 0)
                {
                    debug("error, received:%u\n", response.length());
                    disconnectServer();
                    return Error::TIMEOUT;
                }
                response.append(buf, buf + len);
            }
        }
        else
        {
            break;
        }
    }
    debug("ok, received:%u\n", response.length());
    return Error::SUCCESS;
}

Error HttpClient::post(const std::string &action, const std::string &content, std::string &response)
{
    if (connectServer() != Error::SUCCESS)
        return Error::CONNECTION_FAIL;
    if (sendHtml(action, content) != Error::SUCCESS)
        return Error::SEND_FAIL;
    if (response != "*" && getResponse(response) != Error::SUCCESS)
        return Error::TIMEOUT;
    disconnectServer();
    LOG_ERROR("response:{0}\n", response);
    if (response != "*")
    {
        size_t pos = response.find(' ');
        int code = atoi(response.substr(pos + 1, 3).c_str());
        if (code != 200)
        {
            LOG_ERROR("ERROR RESPONSE: {0}\n", code);
            return Error::VERIFY_FAIL;
        }
        size_t html_pos = response.find("\r\n\r\n", pos);
        if (html_pos == string::npos)
        {
            LOG_ERROR("ERROR RESPONSE: no content length.\n");
            return Error::VERIFY_FAIL;
        }
        html_pos += 4;
        pos = response.find("Content-Length:", pos);
        if (pos == string::npos)
        {
            LOG_ERROR("ERROR RESPONSE: no content length.\n");
            response.erase(0, html_pos);
        }
        else
        {
            pos += 15;
            int pos2 = response.find("\r\n", pos);
            int len = atoi(response.substr(pos, pos2 - pos).c_str());
            response = response.substr(html_pos, len);
        }
    }
    return Error::SUCCESS;
}

}
