
#include "IntellBoxCommon/Utils/Threading/ThreadMoniker.h"
#include "IntellBoxCommon/Utils/Threading/TaskThread.h"

namespace intellBoxSDK {

TaskThread::TaskThread() : m_alreadyStarting{false}, m_moniker{ThreadMoniker::generateMoniker()} {
}

TaskThread::~TaskThread() {
    m_stop = true;
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

bool TaskThread::start(std::function<bool()> jobRunner) {
    if (!jobRunner) {
        return false;
    }

    bool notRunning = false;
    if (!m_alreadyStarting.compare_exchange_strong(notRunning, true)) {
        return false;
    }

    m_oldThread = std::move(m_thread);
    m_thread = std::thread{std::bind(&TaskThread::run, this, std::move(jobRunner))};
    return true;
}

void TaskThread::run(std::function<bool()> jobRunner) {
    if (m_oldThread.joinable()) {
        m_stop = true;
        m_oldThread.join();
    }

    // Reset stop flag and already starting flag.
    m_stop = false;
    m_alreadyStarting = false;
    ThreadMoniker::setThisThreadMoniker(m_moniker);

    while (!m_stop && jobRunner())
        ;
}

}  // namespace intellBoxSDK
