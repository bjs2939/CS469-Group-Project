/**
 * @file playaudio.c
 * @author ** Kenneth Sherwood, Thomas Wintenburg, Bradley Spence **
 * @date ** 10/14/2025 **
 * @brief Contains the main logic for playing mp3 files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <mpg123.h>

#ifndef NO_AUDIO
#include <alsa/asoundlib.h>
#endif

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.mp3>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];

    // ---- mpg123 init ----
    if (mpg123_init() != MPG123_OK) { fprintf(stderr, "mpg123_init failed\n"); return 1; }
    mpg123_handle *mh = mpg123_new(NULL, NULL);
    if (!mh) { fprintf(stderr, "mpg123_new failed\n"); mpg123_exit(); return 1; }

    if (mpg123_open(mh, path) != MPG123_OK) { fprintf(stderr, "Cannot open %s\n", path); goto done_mh; }

    long rate; int channels, enc;
    if (mpg123_getformat(mh, &rate, &channels, &enc) != MPG123_OK) { fprintf(stderr, "getformat failed\n"); goto done_mh; }

    // force 16-bit signed LE
    mpg123_format_none(mh);
    mpg123_format(mh, rate, channels, MPG123_ENC_SIGNED_16);

#ifndef NO_AUDIO
    // ---- ALSA setup ----
    snd_pcm_t *pcm = NULL;
    snd_pcm_hw_params_t *hw = NULL;
    if (snd_pcm_open(&pcm, "default", SND_PCM_STREAM_PLAYBACK, 0) < 0) {
        fprintf(stderr, "ALSA open failed (try setting up PulseAudio/WSLg)\n");
        goto done_mh;
    }
    snd_pcm_hw_params_malloc(&hw);
    snd_pcm_hw_params_any(pcm, hw);
    snd_pcm_hw_params_set_access(pcm, hw, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_hw_params_set_format(pcm, hw, SND_PCM_FORMAT_S16_LE);
    snd_pcm_hw_params_set_channels(pcm, hw, channels);
    unsigned int urate = (unsigned int)rate;
    snd_pcm_hw_params_set_rate_near(pcm, hw, &urate, NULL);
    snd_pcm_uframes_t frames = 1024;
    snd_pcm_hw_params_set_period_size_near(pcm, hw, &frames, NULL);
    if (snd_pcm_hw_params(pcm, hw) < 0) { fprintf(stderr, "ALSA set params failed\n"); snd_pcm_hw_params_free(hw); goto done_pcm; }
    snd_pcm_hw_params_free(hw);
#endif

    // ---- Decode loop ----
    size_t frame_bytes = (size_t)channels * 2; // S16
#ifndef NO_AUDIO
    size_t buffer_bytes = (size_t)1024 * frame_bytes;
#else
    size_t buffer_bytes = 16384; // decode-only
#endif

    unsigned char *buf = (unsigned char*)malloc(buffer_bytes);
#ifndef NO_AUDIO
    if (!buf) { fprintf(stderr, "malloc failed\n"); goto done_pcm; }
#else
    if (!buf) { fprintf(stderr, "malloc failed\n"); goto done_mh; }
#endif

    size_t total_out = 0;
    while (1) {
        size_t got = 0;
        int r = mpg123_read(mh, buf, buffer_bytes, &got);
        if (r == MPG123_DONE) break;
        if (r != MPG123_OK && r != MPG123_NEW_FORMAT) { fprintf(stderr, "decode error\n"); break; }

        total_out += got;

#ifndef NO_AUDIO
        // write to ALSA
        const short *samples = (const short*)buf;
        size_t frames_to_write = got / frame_bytes;
        while (frames_to_write > 0) {
            snd_pcm_sframes_t wrote = snd_pcm_writei(pcm, samples, frames_to_write);
            if (wrote == -EPIPE) { snd_pcm_prepare(pcm); continue; } // XRUN
            if (wrote < 0) { fprintf(stderr, "ALSA write error: %s\n", snd_strerror(wrote)); break; }
            samples += wrote * channels;
            frames_to_write -= wrote;
        }
#endif
    }

    printf("Decoded %zu bytes of PCM\n", total_out);
    free(buf);

#ifndef NO_AUDIO
    snd_pcm_drain(pcm);
done_pcm:
    if (pcm) snd_pcm_close(pcm);
#endif

done_mh:
    mpg123_close(mh);
    mpg123_delete(mh);
    mpg123_exit();
    return 0;
}
