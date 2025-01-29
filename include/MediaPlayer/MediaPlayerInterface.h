#pragma once

#include <cstdint>
#include <memory>
#include "MediaPlayerObserverInterface.h"

namespace intellBoxSDK {

class MediaPlayerInterface {
public:
    /// A type that identifies which source is currently being operated on.
    
    /**
     * Destructor.
     */
    virtual ~MediaPlayerInterface() = default;

    /**
     * Set a url source to play. The source should be set before making calls to any of the playback control APIs. If
     * any source was set prior to this call, that source will be discarded.
     *
     * @note A @c MediaPlayerInterface implementation must handle only one source at a time. An implementation must call
     * @c MediaPlayerObserverInterface::onPlaybackStopped() with the previous source's id if there was a source set.
     *
     * @param url The url to set as the source.
     * @param offset An optional offset parameter to start playing from when a @c play() call is made.
     * @param repeat An optional parameter to play the url source in a loop.
     *
     * @return The @c SourceId that represents the source being handled as a result of this call. @c ERROR will be
     *     returned if the source failed to be set.
     */   
    virtual int play(const std::string& url) = 0;

    /**
     * Stops playing the audio specified by the @c setSource() call.
     *
     * The source must be set before issuing @c stop().
     *
     * Once @c stop() has been called, subsequent @c play() calls will fail.
     * If @c stop() is called when audio has already stopped, @c false will be returned.
     * If the id does not match the id of the active source, then @c false will be returned.
     * If the @c stop() succeeded, @c true will be returned.
     * When @c true is returned, a callback will be made to either @c MediaPlayerObserverInterface::onPlaybackStopped()
     * or to @c MediaPlayerObserverInterface::onPlaybackError().
     *
     * @param id The id of the source on which to operate.
     *
     * @return @c true if the call succeeded, in which case a callback will be made, or @c false otherwise.
     */
    virtual int stop() = 0;

    /**
     * Pauses playing audio specified by the @c setSource() call.
     *
     * The source must be set before issuing @c pause().
     * If @c pause() is called
     * @li without making a @c setSource(), @c false will be returned.
     * @li when audio is not starting/resuming/playing, @c false will be returned.
     * @li when a play() or resume() call has already been made, but no callback has been issued
     *     yet for those functions, the audio stream will pause without playing any audio.  Implementations must call
     *     both @c MediaPlayerObserverInterface::onPlaybackStarted() /
     *     @c MediaPlayerObserverInterface::onPlaybackResumed and @c MediaPlayerObserverInterface::onPlaybackPaused()
     *     in this scenario, as both the @c play() / @c resume() and the @c pause() are required to have corresponding
     *     callbacks.
     *
     * If the id does not match the id of the active source, then @c false will be returned.
     * If the @c pause() succeeded, @c true will be returned.
     * When @c true is returned, a callback will be made to either @c MediaPlayerObserverInterface::onPlaybackPaused()
     * or to @c MediaPlayerObserverInterface::onPlaybackError().
     *
     * @param id The id of the source on which to operate.
     *
     * @return @c true if the call succeeded, in which case a callback will be made, or @c false otherwise.
     */
    virtual int pause() = 0;

    /**
     * Resumes playing the paused audio specified by the @c setSource() call.
     *
     * The source must be set before issuing @c resume().
     * If @c resume() is called
     * @li without making a @c setSource(), @c false will be returned.
     * @li when audio is already playing, @c false will be returned.
     * @li when audio is not paused, @c false will be returned.
     * @li after a resume() call has already been made but no callback or return code has been issued yet, @c false will
     *     be returned.
     *
     * If the id does not match the id of the active source, then @c false will be returned.
     * If the @c resume() succeeded, @c true will be returned.
     * When @c true is returned, a callback will be made to either @c MediaPlayerObserverInterface::onPlaybackResumed()
     * or to @c MediaPlayerObserverInterface::onPlaybackError().
     *
     * @param id The id of the source on which to operate.
     *
     * @return @c true if the call succeeded, in which case a callback will be made, or @c false otherwise.
     */
    virtual int resume() = 0;

    /**
     * Sets an observer to be notified when playback state changes.
     *
     * @param playerObserver The observer to send the notifications to.
     */
    virtual int setPlayVolume(int vol) = 0;
    virtual int getPlayVolume() = 0;

    virtual void addMediaPlayerObserver(std::shared_ptr<MediaPlayerObserverInterface> playerObserver) = 0;
    virtual void removeMediaPlayerObserver(std::shared_ptr<MediaPlayerObserverInterface> playerObserver) = 0;
};

}  // namespace intellBoxSDK
