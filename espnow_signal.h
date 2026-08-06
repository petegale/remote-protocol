#pragma once
#include <stdint.h>
#include <stdbool.h>

/**
 * espnow_signal.h — link signal quality, as pure logic.
 *
 * RSSI reaches a device as a per-frame reading in dBm, from
 * esp_now_recv_info_t.rx_ctrl (or wifi_promiscuous_pkt_t.rx_ctrl on the hub,
 * which is stuck on an SDK whose ESP-NOW callback does not carry it). Three
 * things have to happen to that number before a human should see it, and all
 * three are logic rather than radio — so they live here and are tested on the
 * host.
 *
 * SMOOTHING. A single frame's RSSI swings several dB frame to frame even on a
 * motionless bench. Reporting raw samples would make an indicator flicker
 * constantly and mean nothing.
 *
 * HYSTERESIS. Smoothing alone still leaves a value parked on a threshold
 * flipping between two levels. An indicator that oscillates is worse than one
 * that lags, because it draws the eye to a change that has not happened.
 *
 * BARS, NOT NUMBERS. A single-antenna RSSI reading does not justify a precise-
 * looking dBm on a glanceable display. Four levels is about what the
 * measurement can honestly support, and it is what the question actually needs
 * answering: is this sensor sited well enough?
 */

// No reading. RSSI is always negative in practice, so zero is unambiguous and
// costs no extra field — which matters, because this travels in bytes that
// were reserved padding.
#define ESPNOW_RSSI_NONE 0

typedef enum {
    ESPNOW_SIG_NONE = 0,   // no reading, or below the usable floor
    ESPNOW_SIG_WEAK = 1,
    ESPNOW_SIG_OK   = 2,
    ESPNOW_SIG_GOOD = 3,
} espnow_sig_t;

// Level boundaries in dBm. ESP-NOW keeps working down to roughly -90, so
// "none" here means the link is at the edge rather than merely poor.
#define ESPNOW_SIG_GOOD_DBM (-60)
#define ESPNOW_SIG_OK_DBM   (-75)
#define ESPNOW_SIG_WEAK_DBM (-88)

// dB a reading must clear a boundary by before the level is allowed to change.
// Applied against the level already being shown, so a value sitting exactly on
// a boundary holds where it is instead of alternating.
#define ESPNOW_SIG_HYSTERESIS_DB 3

// Exponential moving average, in integer dBm. `prev` is the last smoothed
// value or ESPNOW_RSSI_NONE to start.
//
// Weight is 1/8. A quarter was tried first and is too fast to do the job: a
// single -90 frame against a settled -55 pulls the average 8 dB, straight
// across a level boundary, which is the exact flicker smoothing exists to
// prevent. An eighth holds the level through one bad frame while still
// settling within a few seconds at sensor frame rates.
#define ESPNOW_RSSI_EMA_SHIFT 3

static inline int espnow_rssi_smooth(int prev, int sample) {
    if (sample >= 0) return prev;                  // not a real reading
    if (prev == ESPNOW_RSSI_NONE) return sample;   // first reading wins outright
    const int delta = sample - prev;
    int step = delta >> ESPNOW_RSSI_EMA_SHIFT;     // arithmetic shift: floors
    // Integer division alone stalls: once |delta| is below the divisor the
    // step rounds to zero and the average parks a dB or two off the true
    // value — which, sitting next to a threshold, is where it matters most.
    // Guarantee at least one dB of movement while any gap remains.
    if (step == 0 && delta != 0) step = (delta > 0) ? 1 : -1;
    return prev + step;
}

static inline espnow_sig_t espnow_sig_from_rssi(int rssi) {
    if (rssi == ESPNOW_RSSI_NONE || rssi >= 0) return ESPNOW_SIG_NONE;
    if (rssi >= ESPNOW_SIG_GOOD_DBM) return ESPNOW_SIG_GOOD;
    if (rssi >= ESPNOW_SIG_OK_DBM)   return ESPNOW_SIG_OK;
    if (rssi >= ESPNOW_SIG_WEAK_DBM) return ESPNOW_SIG_WEAK;
    return ESPNOW_SIG_NONE;
}

// As above, but a level only changes once the reading has cleared the relevant
// boundary by ESPNOW_SIG_HYSTERESIS_DB. Pass the level currently on screen.
static inline espnow_sig_t espnow_sig_from_rssi_hyst(int rssi, espnow_sig_t prev) {
    const espnow_sig_t raw = espnow_sig_from_rssi(rssi);
    if (raw == prev) return prev;
    if (rssi == ESPNOW_RSSI_NONE || rssi >= 0) return ESPNOW_SIG_NONE;
    // Moving up: require clearing the boundary being crossed INTO by the
    // margin. Moving down: require falling below the boundary being left by
    // the same margin. Either way the shown level is the reference point.
    const int m = ESPNOW_SIG_HYSTERESIS_DB;
    if (raw > prev) {
        const int bound = (raw == ESPNOW_SIG_GOOD) ? ESPNOW_SIG_GOOD_DBM
                        : (raw == ESPNOW_SIG_OK)   ? ESPNOW_SIG_OK_DBM
                                                   : ESPNOW_SIG_WEAK_DBM;
        return (rssi >= bound + m) ? raw : prev;
    }
    const int bound = (prev == ESPNOW_SIG_GOOD) ? ESPNOW_SIG_GOOD_DBM
                    : (prev == ESPNOW_SIG_OK)   ? ESPNOW_SIG_OK_DBM
                                                : ESPNOW_SIG_WEAK_DBM;
    return (rssi <= bound - m) ? raw : prev;
}

// ─── Wire packing ───────────────────────────────────────────────────────────
// Four sensors at two bits each in a single byte. This exists because
// display_state_t had exactly two bytes of reserved padding left and a
// per-sensor dBm would have needed four — growing the struct, changing its
// length, and breaking the hub's length-based dispatch for every device that
// had not been reflashed at the same moment. Bars are what gets drawn anyway,
// so the resolution lost here is resolution that was never going to be shown.
#define ESPNOW_SIG_PACK_MAX 4

static inline uint8_t espnow_sig_pack(const espnow_sig_t* levels, int n) {
    uint8_t out = 0;
    if (n > ESPNOW_SIG_PACK_MAX) n = ESPNOW_SIG_PACK_MAX;
    for (int i = 0; i < n; i++)
        out |= (uint8_t)((levels[i] & 0x3) << (i * 2));
    return out;
}

static inline espnow_sig_t espnow_sig_unpack(uint8_t packed, int idx) {
    if (idx < 0 || idx >= ESPNOW_SIG_PACK_MAX) return ESPNOW_SIG_NONE;
    return (espnow_sig_t)((packed >> (idx * 2)) & 0x3);
}
