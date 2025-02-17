#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace intellBoxSDK {

/**
 * A TaskThread executes in sequence until no more tasks exists.
 *
 * @note It's the caller responsibility to restart the @c TaskThread if jobRunner returns false.
 */
class TaskThread {
public:
    /**
     * Constructs a TaskThread to read from the given TaskQueue. This does not start the thread.
     *
     * @params taskQueue A TaskQueue to take tasks from to execute.
     */
    TaskThread();

    /**
     * Destructs the TaskThread.
     */
    ~TaskThread();

    /**
     * Start executing tasks from the given job runner. The task thread will keep running until @c jobRunner
     * returns @c false or @c start gets called again.
     *
     * @param jobRunner Function that should execute jobs. The function should return @c true if there's more tasks
     * to be executed.
     * @return @c true if it succeeds to start the new jobRunner thread; @c false if it fails.
     */
    bool start(std::function<bool()> jobRunner);

private:
    /**
     * Run the @c jobRunner until it returns @c false or @c m_stop is set to true.
     *
     * @param jobRunner Function that should execute the next job. The function should return @c true if a new job
     * still exists.
     */
    void run(std::function<bool()> jobRunner);

    /// The thread to run tasks on.
    std::thread m_thread;

    /// Old thread that will be terminated after start.
    std::thread m_oldThread;

    /// Flag used by the new thread to ensure that the old thread will exit once the current job ends.
    std::atomic_bool m_stop;

    /// Flag used to indicate that there is a new job starting.
    std::atomic_bool m_alreadyStarting;

    /// The task thread moniker.
    std::string m_moniker;
};

}  // namespace intellBox
