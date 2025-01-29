#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/Utils/MediaPlayer/AlsaPlayer.h"

namespace intellBoxSDK {

AlsaPlayer::~AlsaPlayer() {
    m_quitFlag = true;
    m_playCond.notify_all();

    m_playThread.join();

    if (m_handle) {
        snd_pcm_close(m_handle);
        m_handle = nullptr;
    }

    if (m_playFp) {
        fclose(m_playFp);
        m_playFp = nullptr;
    }

    if (m_buffer) {
        delete[] m_buffer;
        m_buffer = nullptr;
    }
}

std::shared_ptr<AlsaPlayer> AlsaPlayer::create(const std::string& playDevice, const std::string& volumeControlName) {
    auto alsaPlayer = std::shared_ptr<AlsaPlayer>(new AlsaPlayer(playDevice, volumeControlName));
    if (alsaPlayer) {
        if (0 == alsaPlayer->initialize()) {
            return alsaPlayer;
        }
    }

    return nullptr;
}

int AlsaPlayer::play(const std::string& url) {
    LOG_INFO("[AlsaPlayer:{0}]play url:{1}", __LINE__, url);
    stop();

    m_url = url;
    m_playFp = fopen(url.c_str(), "rb");
    if (nullptr == m_playFp) {
        LOG_ERROR("open {0} failed.",url.c_str());
        return -1;
    }

    std::unique_lock<std::mutex> lock(m_mutex);
    m_isPlaying = true;
    m_playCond.notify_all();
	notifyPlayStarted();

    return 0;
}

int AlsaPlayer::stop() {
    LOG_INFO("[AlsaPlayer:{0}]stop", __LINE__);
    m_url = "";

    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_isPlaying = false;
    }

    if (m_playFp) {
        fclose(m_playFp);
        m_playFp = nullptr;
    }


    snd_pcm_drop(m_handle);

    return 0;
}

int AlsaPlayer::pause() {
    LOG_INFO("[AlsaPlayer:{0}]pause", __LINE__);
    snd_pcm_pause(m_handle, 1);

    std::unique_lock<std::mutex> lock(m_mutex);
    m_isPlaying = false;

    return 0;
}

int AlsaPlayer::resume() {
    LOG_INFO("[AlsaPlayer:{0}]resume", __LINE__);
    snd_pcm_pause(m_handle, 0);

    std::unique_lock<std::mutex> lock(m_mutex);
    m_isPlaying = true;
    m_playCond.notify_all();

    return 0;
}

int AlsaPlayer::setPlayVolume(int vol) {
    long int newVol = vol;
    if (newVol < 0) {
        newVol = 0;
    }

    if (newVol > 100) {
        newVol = 100;
    }

    if (m_volume) {
        // set volume
        int ret = snd_mixer_selem_set_playback_volume_all(m_volume, newVol);
        if(0 != ret){
            perror("snd_mixer_selem_set_playback_volume_all");
            return -1;
        }
        return 0;
    }

    return -1;
}

int AlsaPlayer::getPlayVolume()  // get volume
{
    long int vol;
    if (m_volume) {
        // get volume
        snd_mixer_selem_get_playback_volume(m_volume, SND_MIXER_SCHN_FRONT_LEFT, &vol);

        return vol;
    }

    return -1;
}

void AlsaPlayer::addMediaPlayerObserver(std::shared_ptr<MediaPlayerObserverInterface> ob) {
    if (ob) {
        std::unique_lock<std::mutex> lock(m_mediaPlayerObserversMutex);
        m_mediaPlayerObservers.insert(ob);
    }
}

void AlsaPlayer::removeMediaPlayerObserver(std::shared_ptr<MediaPlayerObserverInterface> ob) {
    if (ob) {
        std::unique_lock<std::mutex> lock(m_mediaPlayerObserversMutex);
        m_mediaPlayerObservers.erase(ob);
    }
}

AlsaPlayer::AlsaPlayer(const std::string& playDevice, const std::string& volumeControlName) :
        m_playDevice(playDevice),
        m_volumeControlName(volumeControlName),
        m_channels(1),
        m_sampleRate(16000),
        m_handle(nullptr),
        m_volume(nullptr),
        m_playFp(nullptr),
        m_quitFlag(false),
        m_isPlaying(false) {
}

int AlsaPlayer::initialize() {
    LOG_INFO("m_playDevice:{0}", m_playDevice);
    auto ret = snd_pcm_open(&m_handle, m_playDevice.c_str(), SND_PCM_STREAM_PLAYBACK, 0);
    if (0 != ret) {
        return -1;
    }

    ret = snd_pcm_set_params(
        m_handle, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, m_channels, m_sampleRate, 1, 500000);
    if (0 != ret) {
        snd_pcm_close(m_handle);
        m_handle = NULL;
        return -1;
    }

    snd_mixer_selem_id_t* selem_handle;
    snd_mixer_t* mixer_handle;

    // mixer control volume
    if (snd_mixer_open(&mixer_handle, 0) != 0) {
        LOG_ERROR("Unable to open ALSA mixer.");
        snd_pcm_close(m_handle);
        m_handle = nullptr;
        return -1;
    }

    ret = snd_mixer_attach(mixer_handle, "default");
    if (ret != 0) {
        LOG_ERROR("Unable to attach to ALSA mixer.ret:{0}", ret);
        snd_pcm_close(m_handle);
        m_handle = nullptr;

        return -1;
    }

    ret = snd_mixer_selem_register(mixer_handle, NULL, NULL);
    if (ret != 0) {
        LOG_ERROR("Unable to register ALSA mixer.ret:{0}", ret);
        snd_pcm_close(m_handle);
        m_handle = nullptr;
        return -1;
    }
    if (snd_mixer_load(mixer_handle) != 0) {
        LOG_ERROR("Unable to load ALSA mixer.");
        snd_pcm_close(m_handle);
        m_handle = nullptr;

        return -1;
    }

    // find PCM element
    snd_mixer_selem_id_alloca(&selem_handle);
    snd_mixer_selem_id_set_index(selem_handle, 0);
    snd_mixer_selem_id_set_name(selem_handle, m_volumeControlName.c_str());

    m_volume = snd_mixer_find_selem(mixer_handle, selem_handle);
    if (m_volume == nullptr) {
        LOG_ERROR("Unable to find %s volume controls.", m_volumeControlName.c_str());

        snd_pcm_close(m_handle);
        m_handle = nullptr;

        return -1;
    }

    /// 一次写100ms数据
    int frameCount = m_sampleRate / 10;

    /// 2表示一个采样点2个字节(16bit)
    m_bufferSize = frameCount * m_channels * 2;
    m_buffer = new char[m_bufferSize];
    if (!m_buffer) {
        LOG_ERROR("Unable to alloc buffer.");

        snd_pcm_close(m_handle);
        m_handle = nullptr;

        return -1;
    }

    m_playThread = std::thread(std::bind(&AlsaPlayer::playThreadFunc, this));

    return 0;
}

void AlsaPlayer::playThreadFunc() {
    while (!m_quitFlag) {
        while (true) {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (m_isPlaying || m_quitFlag) {
                break;
            }

            m_playCond.wait_for(lock, std::chrono::seconds(5), [=] { return m_isPlaying || m_quitFlag; });
        }

        if (nullptr == m_playFp) {
			LOG_INFO("m_playFp == nullptr");
            continue;
        }

        auto readSize = fread(m_buffer, 1, m_bufferSize, m_playFp);
        if (readSize > 0) {
            auto ret = snd_pcm_writei(m_handle, m_buffer, readSize / (2 * m_channels));
            if (ret < 0) {
                if (ret == -EBADFD) {
                    snd_pcm_prepare(m_handle);
                } else {
                    snd_pcm_recover(m_handle, ret, 1);
                }
            }
        } else {
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_isPlaying = false;
            }

            if (readSize == 0) {
                notifyPlayFinished();
            } else {
                /// notify error
            }
        }
    }
}

void AlsaPlayer::notifyPlayStarted() {
    std::unique_lock<std::mutex> lock(m_mediaPlayerObserversMutex);
    for (auto ob : m_mediaPlayerObservers) {
        ob->onPlayStarted();
    }

    return;
}

void AlsaPlayer::notifyPlayFinished() {
    std::unique_lock<std::mutex> lock(m_mediaPlayerObserversMutex);
    for (auto ob : m_mediaPlayerObservers) {
        ob->onPlayFinished(m_url);
    }

    return;
}
}  // namespace intellBoxSDK
