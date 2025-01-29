#pragma once

#include "MediaPlayerInterface.h"

namespace intellBoxSDK {

class MediaPlayerObserverInterface {
public:
    virtual void onPlayStarted() = 0;

    /**
     * This is an indication to the observer that the @c MediaPlayer finished the source.
     *
     * @note The observer must quickly return to quickly from this callback. Failure to do so could block the @c
     * MediaPlayer from further processing.
     *
     * @param id The id of the source to which this callback corresponds to.
     */
    virtual void onPlayFinished(const std::string& url) = 0;

    /**
     * This is an indication to the observer that the @c MediaPlayer encountered an error. Errors can occur during
     * playback.
     *
     * @note The observer must quickly return from this callback. Failure to do so could block the @c MediaPlayer from
     * further processing.
     *
     * @param id The id of the source to which this callback corresponds to.
     * @param type The type of error encountered by the @c MediaPlayerInterface.
     * @param error The error encountered by the @c MediaPlayerInterface.
     */

    virtual void onPlayPaused(){};

    /**
     * This is an indication to the observer that the @c MediaPlayer has resumed playing the source.
     *
     * @note The observer must quickly return from this callback. Failure to do so could block the @c MediaPlayer from
     * further processing.
     *
     * @param id The id of the source to which this callback corresponds to.
     */
    virtual void onPlayResumed(){};

    /**
     * This is an indication to the observer that the @c MediaPlayer has stopped the source.
     *
     * @note The observer must quickly return from this callback. Failure to do so could block the @c MediaPlayer from
     * further processing.
     *
     * @param id The id of the source to which this callback corresponds to.
     */
    virtual void onPlayStopped(){};
};

}  // namespace intellBoxSDK
