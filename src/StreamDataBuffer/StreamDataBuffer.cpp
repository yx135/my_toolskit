
#include <string.h>

#include "IntellBoxCommon/Utils/StreamDataBuffer/StreamDataBuffer.h"

namespace intellBoxSDK {

std::shared_ptr<StreamDataBuffer> StreamDataBuffer::create(size_t bufferSize) {
    std::shared_ptr<StreamDataBuffer> streamDataBuffer(new StreamDataBuffer(bufferSize));
    if (streamDataBuffer->init()) {
        return streamDataBuffer;
    } else {
        return nullptr;
    }
}

StreamDataBuffer::StreamDataBuffer(size_t bufferSize) :
        m_bufferSize{bufferSize},
        m_front{0},
        m_tail{0},
        m_length{0},
        m_buffer{NULL} {
}

StreamDataBuffer::~StreamDataBuffer() {
    delete[] m_buffer;
    m_buffer = NULL;
}

int StreamDataBuffer::read(void* buf, size_t len, int wait) {
    uint8_t* bufForRead = (uint8_t*)buf;
    std::unique_lock<std::mutex> lock(m_mutex);
    auto iret = m_ConditionVariable.wait_for(lock, std::chrono::milliseconds(wait), [=] { return m_length >= len; });
    if (!iret) {
        return Error::UNDERRUN;
    }

    size_t startIndex = m_front;
    if (m_front + len < m_bufferSize) {
        memcpy(bufForRead, m_buffer + startIndex, len);
    } else {
        size_t sizeReadFirst = m_bufferSize - startIndex;
        memcpy(bufForRead, m_buffer + startIndex, sizeReadFirst);
        memcpy(bufForRead + sizeReadFirst, m_buffer, len - sizeReadFirst);
    }

    m_front = (m_front + len) % m_bufferSize;
    m_length -= len;

    return len;
}

int StreamDataBuffer::write(const void* buf, size_t len) {
    uint8_t* bufToWrite = (uint8_t*)buf;
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_bufferSize - m_length >= len) {
        size_t startIndex = m_tail;
        if (m_tail >= m_front) {
            if ((len + startIndex) <= m_bufferSize) {
                memcpy(m_buffer + startIndex, bufToWrite, len);
            } else {
                memcpy(m_buffer + startIndex, bufToWrite, m_bufferSize - startIndex);
                memcpy(m_buffer, bufToWrite + (m_bufferSize - startIndex), len - (m_bufferSize - startIndex));
            }
        } else {
            memcpy(m_buffer + startIndex, bufToWrite, len);
        }

        m_tail = (m_tail + len) % m_bufferSize;
        m_length += len;
        m_ConditionVariable.notify_all();
        return len;
    } else {
        return Error::OVERRUN;
    }
}

void StreamDataBuffer::reset() {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_front = 0;
    m_tail = 0;
    m_length = 0;
}

bool StreamDataBuffer::init() {
    m_buffer = new uint8_t[m_bufferSize];
    if (NULL != m_buffer) {
        memset(m_buffer, 0, m_bufferSize);
        return true;
    } else {
        return false;
    }
}

}  // namespace intellBoxSDK