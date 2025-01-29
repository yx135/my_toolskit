#pragma once

#include <memory>
#include <mutex>
#include <condition_variable>

namespace intellBoxSDK {

/**
 * This class implement a circle data buffer, there is just one writer and one reader
 */
class StreamDataBuffer {
public:
    /// The error code of StreamDataBuffer method may return
    enum Error {
        /// The buffer overrun when write data
        OVERRUN = -1,

        /// The buffer underrun when read data
        UNDERRUN = -2
    };

    /**
     * Creates a @c StreamDataBuffer.
     *
     * @param bufferSize The max size of circle buffer
     * @return A shared_ptr to a @c StreamDataBuffer if creation was successful and @c nullptr otherwise.
     */
    static std::shared_ptr<StreamDataBuffer> create(size_t bufferSize);

    /**
     * Constructor
     *
     * @param bufferSize The max size of circle buffer
     */
    StreamDataBuffer(size_t bufferSize);

    /// Destructor
    ~StreamDataBuffer();

    /**
     * Write data to circle buffer
     *
     * @param buf The buffer which contain data will push to circle buffer
     * @param len The length of the buf
     * @return The length of data have push to circle buffer
     */
    int write(const void* buf, size_t len);

    /**
     * Read data from circle buffer, this method will block util there is enough data in circle buffer
     *
     * @param buf The buffer will save the read data
     * @param len The length of data will read from buffer
     * @param wait The milliseconds wait for when there are no enough data, then default value is 100 milliseconds
     * @return The length of data have read
     */
    int read(void* buf, size_t len, int wait = 100);

    /// Reset the ring buffer
    void reset();

private:
    // init the StreamDataBuffer
    bool init();

    /// The circle buffer size
    size_t m_bufferSize;

    /// The header of circle buffer
    size_t m_front;

    /// The tail of circle buffer
    size_t m_tail;

    /// length of circle buffer size
    size_t m_length;

    /// A mutex to protect access to the circle buffer.
    std::mutex m_mutex;

    /// Condition variable to signal that enough data can be read.
    std::condition_variable m_ConditionVariable;

    /// Circle buffer
    uint8_t* m_buffer;
};

}  // namespace intellBoxSDK