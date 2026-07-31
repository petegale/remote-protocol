#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/**
 * espnow_client.h — the device side of the hub link, as pure logic.
 *
 * Every device has carried its own copy of this: find the hub's channel,
 * collect an LMK, register an encrypted peer, transmit, notice when the link
 * has died, start again. Four hand-written copies, none under test, and each
 * one got the same subtleties wrong independently. One bug class alone — an
 * unencrypted probe response discarded because the peer was still registered
 * encrypted — surfaced three separate times in a single session, on two
 * different devices, one of them twice by different routes.
 *
 * WHY THIS IS A DECIDER, NOT A DOER
 * =================================
 * Nothing here calls esp_now_*. The state machine returns an ACTION and the
 * device performs it. That is what makes the ordering rules testable on a
 * host — and ordering is where the bugs were:
 *
 *   • The radio must be on the peer's channel BEFORE the peer is registered.
 *     ESP-NOW refuses to transmit to a peer whose channel differs from the
 *     home channel, so every fresh pairing used to lose its first sends.
 *   • Unicast peers must be dropped BEFORE a channel sweep. Probe responses
 *     arrive unencrypted — they carry the LMK, so they cannot be encrypted
 *     with it — and ESP-NOW silently discards an unencrypted frame from a
 *     peer registered as encrypted, below the receive callback, with no
 *     error at either end.
 *   • The peer must be deleted BEFORE its MAC is forgotten, or the
 *     registration outlives every reference to it and can never be removed.
 *
 * Each of those is one line to get wrong and days to find, because the
 * failure is invisible from both ends: 802.11 ACKs are sent before CCMP is
 * validated, so a transmitter cannot tell a delivered frame from a discarded
 * one. That is also why the counters below are part of the contract rather
 * than a debugging afterthought.
 *
 * Transport policy stays with the device — poll interval, sleep, backoff
 * limits — because a battery remote, a mains display and a 60-second sensor
 * genuinely differ. What they should not differ on is any of the above.
 */

// ─── Actions ────────────────────────────────────────────────────────────────
// What the caller must do before calling tick() again. One per tick: each is
// a discrete radio operation, and returning them one at a time is what keeps
// the ordering rules above expressible as a sequence a test can assert on.
typedef enum {
    ESPNOW_ACT_NONE = 0,        // nothing to do; call again later
    ESPNOW_ACT_DROP_PEERS,      // delete every non-broadcast peer
    ESPNOW_ACT_SET_CHANNEL,     // set radio to act_channel
    ESPNOW_ACT_ADD_BCAST_PEER,  // register FF:FF:.. on act_channel, unencrypted
    ESPNOW_ACT_SEND_PROBE,      // broadcast a channel_probe_t
    ESPNOW_ACT_ADD_HUB_PEER,    // register act_mac on act_channel with act_lmk
    ESPNOW_ACT_DEL_HUB_PEER,    // delete act_mac
    ESPNOW_ACT_SEND_DATA,       // link is up; send whatever this device sends
    ESPNOW_ACT_REPORT_LOST,     // link considered down; tell the user
} espnow_action_t;

typedef enum {
    ESPNOW_LINK_SEARCHING = 0,
    ESPNOW_LINK_UP,
    ESPNOW_LINK_LOST,
} espnow_link_t;

// Internal phase. Exposed only so tests can assert on it.
typedef enum {
    ESPNOW_PH_IDLE = 0,
    ESPNOW_PH_SWEEP_DROP,       // about to drop peers, before sweeping
    ESPNOW_PH_SWEEP_SET_CH,
    ESPNOW_PH_SWEEP_ADD_BCAST,
    ESPNOW_PH_SWEEP_SEND,
    ESPNOW_PH_SWEEP_WAIT,
    ESPNOW_PH_LOCK_SET_CH,      // probe answered: channel first, then peer
    ESPNOW_PH_LOCK_ADD_PEER,
    ESPNOW_PH_LINKED,
    ESPNOW_PH_UNPAIR_DEL,       // delete the peer before forgetting the MAC
} espnow_phase_t;

typedef struct {
    uint8_t  chMin, chMax;      // inclusive sweep range
    uint16_t listenMs;          // per-channel wait for a reply
    uint8_t  txFailLimit;       // consecutive failures before re-sweeping
    uint32_t linkTimeoutMs;     // silence after which the link counts as lost
} espnow_cfg_t;

typedef struct {
    espnow_cfg_t   cfg;
    espnow_phase_t phase;

    uint8_t  hubMac[6];
    uint8_t  hubLmk[16];
    bool     haveHub;           // a MAC is known (not necessarily reachable)
    bool     haveLmk;

    uint8_t  channel;           // hub's channel, or 0
    uint8_t  sweepCh;           // channel currently being probed
    uint8_t  sweepTried;

    uint32_t nowMs;
    uint32_t phaseAtMs;
    uint32_t lastRxMs;
    uint8_t  txFails;

    // Outputs for the action just returned.
    uint8_t  act_channel;
    uint8_t  act_mac[6];
    uint8_t  act_lmk[16];

    // Frame accounting. Part of the contract: an encryption or channel
    // mismatch produces silence that looks exactly like a hub that is not
    // transmitting, and counting what reaches the callback is the only way to
    // tell those apart from the device's own logs.
    uint32_t rxFrames;
    uint32_t txAttempts;
    uint32_t txFailures;
    uint32_t sweeps;
} espnow_client_t;

// ─── Setup ──────────────────────────────────────────────────────────────────
static inline void espnow_client_init(espnow_client_t* c, const espnow_cfg_t* cfg) {
    memset(c, 0, sizeof(*c));
    c->cfg   = *cfg;
    c->phase = ESPNOW_PH_IDLE;
}

// Restore a pairing from NVS. The link still has to be proven, so this only
// seeds what to try first — it never reports the link as up.
static inline void espnow_client_restore(espnow_client_t* c, const uint8_t mac[6],
                                         const uint8_t lmk[16], uint8_t channel) {
    memcpy(c->hubMac, mac, 6);
    c->haveHub = true;
    if (lmk) { memcpy(c->hubLmk, lmk, 16); c->haveLmk = true; }
    c->channel = channel;
}

// ─── Events ─────────────────────────────────────────────────────────────────
static inline void espnow_client_set_time(espnow_client_t* c, uint32_t ms) {
    c->nowMs = ms;
}

// A probe response arrived. `mac` is the sender; a device already paired to a
// different hub should not call this — that check belongs with the caller,
// which has the stored identity to compare against.
static inline void espnow_client_on_probe_reply(espnow_client_t* c,
                                                const uint8_t mac[6],
                                                const uint8_t lmk[16],
                                                uint8_t channel) {
    c->rxFrames++;
    memcpy(c->hubMac, mac, 6);
    c->haveHub = true;
    if (lmk) {
        bool any = false;
        for (int i = 0; i < 16; i++) if (lmk[i]) { any = true; break; }
        if (any) { memcpy(c->hubLmk, lmk, 16); c->haveLmk = true; }
    }
    c->channel   = channel;
    c->txFails   = 0;
    c->lastRxMs  = c->nowMs;
    // Channel BEFORE peer — the ordering that cost the first sends after
    // every pairing until it was made explicit here.
    c->phase     = ESPNOW_PH_LOCK_SET_CH;
    c->phaseAtMs = c->nowMs;
}

// Any frame from the hub that proves the link works.
static inline void espnow_client_on_hub_frame(espnow_client_t* c) {
    c->rxFrames++;
    c->lastRxMs = c->nowMs;
    c->txFails  = 0;
}

static inline void espnow_client_on_tx_result(espnow_client_t* c, bool ok) {
    c->txAttempts++;
    if (ok) { c->txFails = 0; return; }
    c->txFailures++;
    if (c->txFails < 255) c->txFails++;
}

// The hub asked this device to forget it.
static inline void espnow_client_on_unpair(espnow_client_t* c) {
    // Delete the peer first; the MAC is cleared only once that has happened,
    // because a registration whose address has been forgotten can never be
    // removed and will silently swallow every unencrypted reply thereafter.
    c->phase     = ESPNOW_PH_UNPAIR_DEL;
    c->phaseAtMs = c->nowMs;
}

// ─── Tick ───────────────────────────────────────────────────────────────────
static inline void espnow__begin_sweep(espnow_client_t* c) {
    c->phase     = ESPNOW_PH_SWEEP_DROP;
    c->phaseAtMs = c->nowMs;
    c->sweepTried = 0;
    // Start on the last known channel when there is one: the hub usually has
    // not moved, so the first probe is usually the only one needed.
    c->sweepCh = c->channel ? c->channel : c->cfg.chMin;
    c->sweeps++;
}

// Returns the next action. `wantSend` is the caller's own policy — whether it
// has something to transmit right now — which is the one thing that genuinely
// differs between a battery remote, a mains display and a sleeping sensor.
static inline espnow_action_t espnow_client_tick(espnow_client_t* c, bool wantSend) {
    const espnow_cfg_t* k = &c->cfg;
    const uint32_t inPhase = c->nowMs - c->phaseAtMs;

    switch (c->phase) {
    case ESPNOW_PH_IDLE:
        espnow__begin_sweep(c);
        return espnow_client_tick(c, wantSend);

    case ESPNOW_PH_UNPAIR_DEL:
        if (!c->haveHub) { espnow__begin_sweep(c); return ESPNOW_ACT_DROP_PEERS; }
        memcpy(c->act_mac, c->hubMac, 6);
        // Only now is it safe to forget it.
        memset(c->hubMac, 0, 6);
        memset(c->hubLmk, 0, 16);
        c->haveHub = c->haveLmk = false;
        c->channel = 0;
        espnow__begin_sweep(c);
        return ESPNOW_ACT_DEL_HUB_PEER;

    case ESPNOW_PH_SWEEP_DROP:
        // Before anything else in a sweep. An encrypted registration left
        // over from the previous link discards the very probe response the
        // sweep exists to receive.
        c->phase     = ESPNOW_PH_SWEEP_SET_CH;
        c->phaseAtMs = c->nowMs;
        return ESPNOW_ACT_DROP_PEERS;

    case ESPNOW_PH_SWEEP_SET_CH:
        c->act_channel = c->sweepCh;
        c->phase       = ESPNOW_PH_SWEEP_ADD_BCAST;
        c->phaseAtMs   = c->nowMs;
        return ESPNOW_ACT_SET_CHANNEL;

    case ESPNOW_PH_SWEEP_ADD_BCAST:
        c->act_channel = c->sweepCh;
        c->phase       = ESPNOW_PH_SWEEP_SEND;
        c->phaseAtMs   = c->nowMs;
        return ESPNOW_ACT_ADD_BCAST_PEER;

    case ESPNOW_PH_SWEEP_SEND:
        c->phase     = ESPNOW_PH_SWEEP_WAIT;
        c->phaseAtMs = c->nowMs;
        return ESPNOW_ACT_SEND_PROBE;

    case ESPNOW_PH_SWEEP_WAIT: {
        if (inPhase < k->listenMs) return ESPNOW_ACT_NONE;
        const uint8_t span = (uint8_t)(k->chMax - k->chMin + 1);
        if (++c->sweepTried >= span) {
            // Whole sweep, no answer. Report once, then keep sweeping —
            // giving up entirely would need a human to notice.
            c->sweepTried = 0;
            c->phase      = ESPNOW_PH_SWEEP_DROP;
            c->phaseAtMs  = c->nowMs;
            return ESPNOW_ACT_REPORT_LOST;
        }
        c->sweepCh = (uint8_t)(k->chMin +
                     ((c->sweepCh - k->chMin + 1) % span));
        c->phase     = ESPNOW_PH_SWEEP_SET_CH;
        c->phaseAtMs = c->nowMs;
        return espnow_client_tick(c, wantSend);
    }

    case ESPNOW_PH_LOCK_SET_CH:
        c->act_channel = c->channel;
        c->phase       = ESPNOW_PH_LOCK_ADD_PEER;
        c->phaseAtMs   = c->nowMs;
        return ESPNOW_ACT_SET_CHANNEL;

    case ESPNOW_PH_LOCK_ADD_PEER:
        memcpy(c->act_mac, c->hubMac, 6);
        memcpy(c->act_lmk, c->haveLmk ? c->hubLmk : c->act_lmk, 16);
        if (!c->haveLmk) memset(c->act_lmk, 0, 16);
        c->act_channel = c->channel;
        c->phase       = ESPNOW_PH_LINKED;
        c->phaseAtMs   = c->nowMs;
        c->lastRxMs    = c->nowMs;
        return ESPNOW_ACT_ADD_HUB_PEER;

    case ESPNOW_PH_LINKED:
        // Two independent ways to notice a dead link. Consecutive TX failures
        // catch a hub that has gone; silence catches one that is still
        // ACKing at the MAC layer while discarding everything above it, which
        // no transmitter can detect any other way.
        if (c->txFails >= k->txFailLimit ||
            (c->nowMs - c->lastRxMs) > k->linkTimeoutMs) {
            espnow__begin_sweep(c);
            return espnow_client_tick(c, wantSend);
        }
        if (wantSend) return ESPNOW_ACT_SEND_DATA;
        return ESPNOW_ACT_NONE;
    }
    return ESPNOW_ACT_NONE;
}

static inline espnow_link_t espnow_client_link(const espnow_client_t* c) {
    if (c->phase == ESPNOW_PH_LINKED) return ESPNOW_LINK_UP;
    return c->haveHub ? ESPNOW_LINK_LOST : ESPNOW_LINK_SEARCHING;
}
