#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <thread>
#include <condition_variable>

#include "alsa/asoundlib.h"
#include "IntellBoxCommon/Utils/MediaPlayer/MediaPlayerInterface.h"

namespace intellBoxSDK {

class AlsaPlayer : public MediaPlayerInterface {
public:
    ~AlsaPlayer();
    static std::shared_ptr<AlsaPlayer> create(
        const std::string& playDevice = "dmixersoftvol",
        const std::string& volumeControlName = "dmixersoftvol");

    /// @name MediaPlayerInterface Functions
    /// @{
    int play(const std::string& url) override;
    int stop() override;
    int pause() override;
    int resume() override;
    int setPlayVolume(int vol) override;
    int getPlayVolume() override;

    void addMediaPlayerObserver(std::shared_ptr<MediaPlayerObserverInterface> ob) override;
    void removeMediaPlayerObserver(std::shared_ptr<MediaPlayerObserverInterface> ob) override;
    /// @}

private:
    const int ELEMENT_BY_NUMID = 1;
    AlsaPlayer(const std::string& playDevice, const std::string& volumeControlName);
    int initialize();
    void playThreadFunc();

    void notifyPlayStarted();
    void notifyPlayFinished();

    std::string m_playDevice;
    std::string m_volumeControlName;

    int m_channels;
    int m_sampleRate;

    snd_pcm_t* m_handle;
    snd_mixer_elem_t* m_volume;

    FILE* m_playFp;

    bool m_quitFlag;
    bool m_isPlaying;
    std::thread m_playThread;

    int m_bufferSize;
    char* m_buffer;

    std::mutex m_mutex;
    std::condition_variable m_playCond;

    std::string m_url;

    mutable std::mutex m_mediaPlayerObserversMutex;
    std::unordered_set<std::shared_ptr<MediaPlayerObserverInterface>> m_mediaPlayerObservers;
};

}  // namespace intellBoxSDK
