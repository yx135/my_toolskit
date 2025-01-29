#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/Utils/Timer/Timer.h"

namespace intellBoxSDK {

Timer::Timer() : m_running(false), m_stopping(false) {
}

Timer::~Timer() {
    stop();
}

void Timer::stop() {
    {
        std::lock_guard<std::mutex> lock(m_waitMutex);
        if (m_running) {
            m_stopping = true;
        }
        m_waitCondition.notify_all();
    }

    if (std::this_thread::get_id() != m_thread.get_id() && m_thread.joinable()) {
        m_thread.join();
    }
}

bool Timer::isActive() const {
    return m_running;
}

bool Timer::activate() {
    return !m_running.exchange(true);
}

}  // namespace intellBoxSDK