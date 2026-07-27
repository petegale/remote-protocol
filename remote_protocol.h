#pragma once

/**
 * remote_protocol.h
 *
 * Shared ESP-NOW wire-format definitions for the sensor_hub, remote, and
 * sensor-node projects.  Include this header in all three to ensure packet
 * structures stay in sync.
 *
 * What lives here: packet structs, enums, magic bytes, flag bits, battery
 * thresholds, and WiFi channel range constants that every node needs.
 *
 * What does NOT live here: project-local timing constants
 * (ESPNOW_ACK_TIMEOUT_MS, CHANNEL_PROBE_LISTEN_MS, MAX_TX_RETRIES,
 * DEBOUNCE_MS, LONG_PRESS_MS, etc.) — those live in each project's config.h.
 *
 * Submodule usage:
 *   git submodule add https://github.com/petegale/remote-protocol protocol
 *   Then in platformio.ini:
 *     build_flags = -I protocol
 *
 * Protocol version history
 * ========================
 * 0x01 — initial: sensor_packet_t (tank-only, 7 bytes)
 * 0x02 — May 2026: sensor_packet_t replaced by sensor_v2_packet_t (8 bytes)
 *         with sensor_type discriminator; UDP $XDR transport removed from hub.
 *         All three firmwares (hub, remote, sensor-node) must match.
 * 0x03 — May 2026: device_id renamed to channel in sensor_v2_packet_t (same
 *         wire size, same position). Hub now routes by ESP-NOW sender MAC
 *         instead of device_id, removing the USB serial config step.
 *         channel is reserved for future multi-sensor boards (send 0 for now).
 * 0x04 — Jun 2026: added SENSOR_TYPE_TANK_RESISTIVE (0x06) for resistive-sender
 *         tank nodes (typically water tanks with a wirewound float-arm sender).
 *         value = raw 12-bit ADC counts (0..4095). Same packet shape and length
 *         as SENSOR_TYPE_TANK; hub feeds counts through the same per-slot
 *         calibration interpolation as wired ADC tanks. No struct changes —
 *         a 0x03 node still parses correctly at a 0x04 hub and vice versa,
 *         but a 0x03 hub will not know how to interpret the new type code.
 * 0x05 — Jun 2026: AES-128 CCMP encryption for all unicast ESP-NOW links.
 *         Breaking changes:
 *         • Hub responds to probes with probe_response_t (20 bytes, includes LMK)
 *           instead of re-using channel_probe_t (4 bytes).
 *         • Added hub_response_t (3 bytes) for hub→device responses (UNPAIR).
 *         • Hub only responds to probes from paired devices OR when in
 *           user-initiated pairing mode (60 s window). All unicast links use
 *           AES-128 CCMP via esp_now_add_peer() with a per-link LMK generated
 *           by the hub during pairing. LMK is transmitted in the clear during
 *           the probe exchange; physical proximity is the security model.
 *         • Hub MAC allowlist: commands from non-paired remotes are dropped;
 *           sensor data from unconfigured MACs are dropped outside pairing mode.
 *         • ESPNOW_PMK must be set on all devices via esp_now_set_pmk().
 * 0x07 — Jul 2026: house-battery telemetry in display_state_t (24 → 30
 *         bytes). The hub listens to a Victron battery monitor's BLE
 *         "Instant Readout" advertisements and forwards SoC / current /
 *         voltage / charging state to the display in the same state
 *         response. batt_soc_pct = DISPLAY_BATT_NO_DATA (0xFF) when no
 *         Victron is configured or the reading is stale — displays fall
 *         back to the tank-only layout. Breaking: version-checked packets
 *         (display_request_t, display_state_t) require hub and display to
 *         be flashed together. Sensor + remote packets unchanged.
 * 0x06 — Jul 2026: added M5Paper display-node class (petegale/sensor-display).
 *         Additive — existing v0.05 sensors and remotes continue to work
 *         against a v0.06 hub without changes.
 *         New packets:
 *         • display_request_t  (6 bytes)  — display → hub, "send state now"
 *         • display_state_t   (24 bytes)  — hub → display, tank levels +
 *           UTC time (from NMEA2000 PGN 126992) + hub uptime
 *         New hub pairing mode PAIRING_DISPLAY reuses the v0.05 probe → LMK →
 *         encrypted-peer flow verbatim. Added FLAG_BATT_CHARGING (0x10) for
 *         display battery state. No existing struct shape or size changed.
 */

#include <stdint.h>

// ============================================================
// PROTOCOL VERSION
// Increment when packet structures change. All nodes on the
// same network must use the same version.
// ============================================================
#define PROTOCOL_VERSION        0x07

// ============================================================
// VERSION COMPATIBILITY — read this before bumping the version
// ============================================================
// PROTOCOL_VERSION is one constant, but the packet families it covers
// have not all changed at the same time. Checking every inbound packet
// for exact equality means a bump made for ONE family silently drops
// traffic from every device that speaks the others.
//
// That is not hypothetical: the v0.07 bump — made purely to grow
// display_state_t — meant a v0.07 hub dropped sensor data and remote
// commands from v0.06 nodes, killing tank readings and the autopilot
// buttons, with no diagnostic beyond silence.
//
// So each family declares the oldest version whose wire layout is still
// identical to today's. Receivers accept anything from that floor
// upward. Length-dispatch plus the static_asserts below are what
// actually guarantee the layout; the floor guards *meaning*.
//
// RULE: if you change a packet's size, the length-dispatch handles it.
// If you change what a field MEANS without changing the size, you must
// raise that family's floor to the new version.
#define SENSOR_PACKET_MIN_VERSION   0x02  // sensor_v2_packet_t: unchanged since v0.02
#define REMOTE_PACKET_MIN_VERSION   0x02  // remote_packet_t:    unchanged since v0.02
#define DISPLAY_PACKET_MIN_VERSION  0x07  // display packets grew a battery block in v0.07

#ifdef __cplusplus
// Pure predicates so receivers share one rule — and so it can be
// unit-tested on the host, which is where this class of bug is cheapest
// to catch.
static inline bool sensor_packet_version_ok(uint8_t v) {
    return v >= SENSOR_PACKET_MIN_VERSION;
}
static inline bool remote_packet_version_ok(uint8_t v) {
    return v >= REMOTE_PACKET_MIN_VERSION;
}
static inline bool display_packet_version_ok(uint8_t v) {
    return v >= DISPLAY_PACKET_MIN_VERSION;
}
#endif

// ============================================================
// ESP-NOW ENCRYPTION
// Fixed PMK shared by all devices in a network.  The actual
// per-link session key is derived from PMK + per-peer LMK.
// LMK is generated randomly by the hub during pairing and
// transmitted in the clear in probe_response_t.
// All devices must call esp_now_set_pmk(ESPNOW_PMK) after
// esp_now_init() and before adding any encrypted peer.
// ============================================================
#define ESPNOW_PMK { \
  0x6e,0x61,0x76,0x5f,0x68,0x75,0x62, \
  0x5f,0x76,0x30,0x35,0x5f,0x70,0x6d,0x6b,0x21 }

// ============================================================
// HUB RESPONSE FLAGS (hub_response_t.flags)
// ============================================================
#define HUB_RESP_FLAG_UNPAIR    0x01    // hub is revoking this device's pairing
#define HUB_RESP_FLAG_UPDATE    0x02    // a firmware update is waiting for you

// ============================================================
// MAGIC BYTES — channel probe / beacon packet identification
// ============================================================
#define PROBE_MAGIC_0           0xAB
#define PROBE_MAGIC_1           0xCD
#define PROBE_TYPE_REQUEST      0x01
#define PROBE_TYPE_RESPONSE     0x02

// ============================================================
// COMMAND CODES
// Format: 0xXY  X=button-group (1=A,2=B,3=C,4=chord)
//               Y=gesture (1=single,2=double,3=long)
// Gaps are intentional — leave room for future expansion
// without breaking existing command assignments.
// ============================================================
typedef enum : uint8_t {
    CMD_NONE            = 0x00,

    // Button A (removed in Phase 2 — 2-button remote; reserved)
    CMD_A_SINGLE        = 0x11,
    CMD_A_DOUBLE        = 0x12,
    CMD_A_LONG          = 0x13,

    // Button B (port — steer to port)
    CMD_B_SINGLE        = 0x21,     // −1 degree
    CMD_B_DOUBLE        = 0x22,     // unused (Phase 2: no length classification)
    CMD_B_LONG          = 0x23,     // −10 degrees (backward-compat; remote uses auto-repeat)

    // Button C (starboard — steer to starboard)
    CMD_C_SINGLE        = 0x31,     // +1 degree
    CMD_C_DOUBLE        = 0x32,     // unused (Phase 2)
    CMD_C_LONG          = 0x33,     // +10 degrees (backward-compat; remote uses auto-repeat)

    // Chords (multi-button)
    CMD_AB_CHORD        = 0x41,     // unused
    CMD_AC_CHORD        = 0x42,     // unused
    CMD_BC_CHORD        = 0x43,     // AUTOPILOT TOGGLE (engage / disengage)
    CMD_ABC_CHORD       = 0x44,     // unused

    // System commands
    CMD_BATT_CRITICAL   = 0xF0,     // battery critically low, sent before lockout
    CMD_PING            = 0xFE,     // channel-probe result / keepalive
    CMD_INVALID         = 0xFF,

} command_t;

// ============================================================
// FLAG BITS (remote_packet_t.flags, sensor_v2_packet_t.flags,
// display_request_t.flags)
// ============================================================
#define FLAG_BATT_LOW           0x01    // battery <= 20%
#define FLAG_BATT_CRITICAL      0x02    // battery <= 10%
#define FLAG_TX_RETRY           0x04    // this is a retry attempt
#define FLAG_CHANNEL_CHANGED    0x08    // remote had to rescan for channel
#define FLAG_BATT_CHARGING      0x10    // (display_request_t) USB charging active

// ============================================================
// MAIN COMMAND PACKET (remote → hub)
// 5 bytes. Hub dispatches by length: 4=probe, 5=remote, 8=sensor.
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t     protocol_version;   // must match PROTOCOL_VERSION
    uint8_t     command;            // command_t value
    uint8_t     battery_pct;        // 0–100
    uint8_t     flags;              // FLAG_* bitmask
    uint8_t     sequence;           // rolling 0–255; hub detects drops
} remote_packet_t;

// ============================================================
// CHANNEL PROBE REQUEST (device → hub, broadcast during channel scan)
// 4 bytes.  Devices broadcast on each channel; hub responds
// with probe_response_t on its current channel.
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t     magic[2];           // PROBE_MAGIC_0, PROBE_MAGIC_1
    uint8_t     type;               // PROBE_TYPE_REQUEST
    uint8_t     channel;            // always 0 in request
} channel_probe_t;

// channel_probe_t is the REQUEST; the old alias is kept as-is for the hub's
// length-dispatch (sizeof == 4).  Do NOT add fields — it would break dispatch.

// ============================================================
// PROBE RESPONSE (hub → device, unicast)
// 20 bytes.  Hub sends this after receiving a channel_probe_t REQUEST.
// In pairing mode: contains a freshly generated random LMK.
// For re-probes from known devices: contains the previously stored LMK.
// Devices must check: if lmk is non-zero, update stored LMK and re-register
// the hub peer with encrypt=true; otherwise keep the existing LMK.
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t     magic[2];           // PROBE_MAGIC_0, PROBE_MAGIC_1
    uint8_t     type;               // PROBE_TYPE_RESPONSE
    uint8_t     channel;            // hub's current WiFi channel
    uint8_t     lmk[16];            // AES-128 CCMP LMK for this link
} probe_response_t;

// ============================================================
// HUB RESPONSE PACKET (hub → device, unicast)
// 3 bytes.  Sent by hub after processing a device command packet.
// Currently used for UNPAIR (flag HUB_RESP_FLAG_UNPAIR).
// Device listens for ≥ 20 ms after TX ACK to receive this.
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t     magic[2];           // PROBE_MAGIC_0, PROBE_MAGIC_1
    uint8_t     flags;              // HUB_RESP_FLAG_* bitmask
} hub_response_t;

// ============================================================
// SENSOR TYPES (sensor_v2_packet_t.sensor_type)
// The `value` field is interpreted per type — see each entry.
// ============================================================
typedef enum : uint8_t {
    SENSOR_TYPE_NONE           = 0x00,
    SENSOR_TYPE_TANK           = 0x01,  // value = level in mm (raw DS1603L distance)
    SENSOR_TYPE_TEMP           = 0x02,  // value = centidegrees C  (2150 = 21.50 C)
    SENSOR_TYPE_RPM            = 0x03,  // value = revolutions per minute
    SENSOR_TYPE_VOLTAGE        = 0x04,  // value = centivolts (1280 = 12.80 V)  [reserved]
    SENSOR_TYPE_PRESSURE       = 0x05,  // value = kPa                          [reserved]
    SENSOR_TYPE_TANK_RESISTIVE = 0x06,  // value = raw 12-bit ADC counts (0..4095)
                                        // resistive-sender tank (water/grey/etc).
                                        // Hub maps counts→% via per-slot calibration,
                                        // same path as wired ADC tanks.
} sensor_type_t;

// ============================================================
// SENSOR NODE PACKET v2 (sensor-node → hub)
// 8 bytes. Size is distinct from remote_packet_t (5) and
// channel_probe_t (4) so the hub RX callback dispatches by length.
//
// Hub routing: the hub identifies this node by the ESP-NOW sender MAC
// address provided by the radio hardware — NOT by the channel field.
// channel is reserved for future boards with multiple sensors; send 0.
//
// value units by sensor_type:
//   TANK             0..32767 mm        (DS1603L max ~5 m)
//   TEMP           -32768..32767 centi-°C  (-327.68..327.67 °C)
//   RPM              0..32767 rpm
//   VOLTAGE          0..32767 centivolts
//   TANK_RESISTIVE      0..4095 raw 12-bit ADC counts
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t  protocol_version;   // must match PROTOCOL_VERSION
    uint8_t  channel;            // reserved; always 0 (was device_id in v0.02)
    uint8_t  sensor_type;        // sensor_type_t
    int16_t  value;              // units per sensor_type (signed)
    uint8_t  battery_pct;        // 0–100; 100 for wired nodes
    uint8_t  sequence;           // rolling 0–255 for dedup
    uint8_t  flags;              // FLAG_BATT_LOW, FLAG_BATT_CRITICAL, FLAG_TX_RETRY
} sensor_v2_packet_t;

// ============================================================
// DISPLAY NODE (M5Paper tank gauge — petegale/sensor-display)
// Added in v0.06. The display is a pull client: it sleeps deeply
// and wakes periodically to request current state from the hub.
// ============================================================

// Display sub-packet type codes (display_request_t.type, display_state_t.type).
// Kept distinct from PROBE_TYPE_* so a future shared "type" dispatch
// is unambiguous.
#define DISPLAY_REQ_STATE       0x01    // "Send me current state"
#define DISPLAY_RESP_STATE      0x02    // Hub response carrying state

// Maximum tanks reported in a single state packet. Sized for the v1
// M5Paper layout (two side-by-side tiles). Hub picks the first N
// active tanks from g_tanks[] when populating the response.
#define MAX_DISPLAY_TANKS       2

// Fluid types for display_state_t.tanks[].fluid_type. Distinct from
// sensor_type_t — these are presentation tags, not measurement
// modalities. Hub maps the TankConfig.fluidType string ("fuel" / "water" /
// "grey" / "black" / "oil" / "live-well") into one of these codes.
#define DISPLAY_FLUID_FUEL      0x00
#define DISPLAY_FLUID_WATER     0x01
#define DISPLAY_FLUID_GREY      0x02
#define DISPLAY_FLUID_BLACK     0x03
#define DISPLAY_FLUID_OIL       0x04
#define DISPLAY_FLUID_LIVEWELL  0x05

// Sentinel level value meaning "no data" / "uncalibrated". Display
// renders these tiles with "--" instead of a percentage and no
// pale-grey fill.
#define DISPLAY_LEVEL_NO_DATA   0xFF

// Sentinels for utc_days / utc_seconds when the hub has not yet
// received a System Time PGN (126992) on the NMEA2000 bus.
#define DISPLAY_UTC_DAYS_NONE   0xFFFF

// House-battery sentinel + flags (v0.07). batt_soc_pct is set to
// DISPLAY_BATT_NO_DATA when no Victron monitor is configured on the hub
// or the last reading is stale; displays render the tank-only layout.
#define DISPLAY_BATT_NO_DATA    0xFF
#define DISPLAY_BATT_FLAG_CHARGING  0x01    // current into the bank

// ============================================================
// DISPLAY REQUEST (display → hub, unicast encrypted)
// 6 bytes. Distinct from remote_packet_t (5) and channel_probe_t (4).
// Hub dispatches on length 6 → build display_state_t and reply.
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t     protocol_version;   // must match PROTOCOL_VERSION
    uint8_t     type;               // DISPLAY_REQ_STATE
    uint8_t     battery_pct;        // 0–100, display's current cell %
    uint8_t     flags;              // FLAG_BATT_LOW, FLAG_BATT_CRITICAL,
                                    // FLAG_BATT_CHARGING
    uint8_t     sequence;           // rolling 0–255 for hub dedup
    uint8_t     reserved;           // padding to 6 bytes (dispatch-distinct)
} display_request_t;

// ============================================================
// DISPLAY STATE (hub → display, unicast encrypted)
// 30 bytes (v0.07; was 24 in v0.06). Distinct from probe_response_t (20)
// and hub_response_t (3). Hub populates from current g_tanks[] state,
// state.h UTC globals, and the Victron house-battery reading (if any).
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t     protocol_version;   // must match PROTOCOL_VERSION
    uint8_t     type;               // DISPLAY_RESP_STATE
    uint8_t     n_tanks;            // 0..MAX_DISPLAY_TANKS
    uint8_t     flags;              // reserved for future health bits
    uint32_t    hub_uptime_s;       // seconds since hub boot
    uint16_t    utc_days;           // PGN 126992 days since 1970-01-01,
                                    // or DISPLAY_UTC_DAYS_NONE if no GPS
    float       utc_seconds;        // PGN 126992 seconds since midnight UTC
    struct {
        uint8_t fluid_type;         // DISPLAY_FLUID_*
        uint8_t level_pct;          // 0..100, or DISPLAY_LEVEL_NO_DATA
        uint8_t reserved[2];        // future expansion (capacity, etc.)
    } tanks[MAX_DISPLAY_TANKS];     // = 4 × 2 = 8 bytes
    // House battery (v0.07) — from the hub's Victron BLE listener.
    uint8_t     batt_soc_pct;       // 0..100 true SoC, or DISPLAY_BATT_NO_DATA
    uint8_t     batt_flags;         // DISPLAY_BATT_FLAG_* bitmask
    int16_t     batt_current_dA;    // deciamps; + = charging, − = discharging
    uint16_t    batt_voltage_cV;    // centivolts (1261 = 12.61 V)
    uint8_t     reserved[2];        // pad to 30 bytes (length-dispatch
                                    // distinct from probe_response_t=20)
} display_state_t;

// ============================================================
// OTA — firmware update over ESP-NOW (any device class)
// Full design: sensor_hub/SPEC-ota.md
//
// Deliberately NOT version-gated. Every struct below is keyed on the
// probe magic bytes and carries no protocol_version field, because the
// update path must keep working across future protocol changes — a
// trigger that rode on a version-checked packet would be unreachable in
// exactly the situation that needs it (see test_protocol_compat).
//
// The trigger itself is HUB_RESP_FLAG_UPDATE in the existing 3-byte
// hub_response_t, which every device class already listens for. It is
// queued by the hub, so offline sensors, a sleeping remote and a
// 15-minute-cycle display all collect it when they next transmit.
// ============================================================
#define OTA_MSG_INFO            0x06    // device → hub, unsolicited: this is what I am
#define OTA_MSG_REQUEST         0x01    // device → hub: what have you got for me?
#define OTA_MSG_OFFER           0x02    // hub → device: image metadata, or none
#define OTA_MSG_CHUNK           0x03    // hub → device: payload
#define OTA_MSG_ACK             0x04    // device → hub: next chunk wanted
#define OTA_MSG_RESULT          0x05    // device → hub: applied / failed

// Board identity. The hub must never guess: flashing a C3 image onto an
// M5Atom, or a tank build onto an RPM node, would brick it.
#define OTA_BOARD_UNKNOWN       0x00
#define OTA_BOARD_M5ATOM        0x01
#define OTA_BOARD_C3ZERO        0x02
#define OTA_BOARD_M5PAPER       0x03
#define OTA_BOARD_WAVESHARE43B  0x04
#define OTA_BOARD_REMOTE_C6     0x05

// ota_request_t.flags
#define OTA_REQ_FLAG_CHARGING   0x01    // mains or charging — safe to update
#define OTA_REQ_FLAG_BATTERY    0x02    // battery powered; respect charge-gating

// ota_offer_t.flags
#define OTA_OFFER_FLAG_NONE     0x01    // nothing suitable — stand down

// ota_ack_t.state
#define OTA_STATE_READY         0x00
#define OTA_STATE_RECEIVING     0x01
#define OTA_STATE_APPLIED       0x02    // written + verified, about to reboot
#define OTA_STATE_FAILED        0x03
#define OTA_STATE_DEFERRED      0x04    // battery too low; will retry when charged

// ota_ack_t.error
#define OTA_ERR_NONE            0x00
#define OTA_ERR_BEGIN           0x01    // esp_ota_begin failed (image too big?)
#define OTA_ERR_WRITE           0x02
#define OTA_ERR_MD5             0x03    // integrity check failed — image discarded
#define OTA_ERR_TIMEOUT         0x04

#define OTA_BUILD_ENV_LEN       26      // "tank-ultrasonic-m5atom" + NUL, rounded
#define OTA_VERSION_LEN         16
#define OTA_CHUNK_DATA_MAX      200

// 47 bytes. Identity is asserted by the device, never inferred by the hub.
//
// Sent in two situations, distinguished by `type`:
//   OTA_MSG_INFO     unsolicited, at boot and periodically. Lets the hub
//                    know what every device is *before* anyone asks for an
//                    update, which is what makes "click Update and the hub
//                    fetches the right image" possible at all.
//   OTA_MSG_REQUEST  in response to HUB_RESP_FLAG_UPDATE: ready to receive.
typedef struct __attribute__((packed)) {
    uint8_t magic[2];                       // PROBE_MAGIC_0, PROBE_MAGIC_1
    uint8_t type;                           // OTA_MSG_INFO | OTA_MSG_REQUEST
    uint8_t flags;                          // OTA_REQ_FLAG_*
    uint8_t board;                          // OTA_BOARD_*
    char    build_env[OTA_BUILD_ENV_LEN];   // manifest key, NUL-terminated
    char    fw_version[OTA_VERSION_LEN];    // what it is running right now
} ota_request_t;

// 44 bytes.
typedef struct __attribute__((packed)) {
    uint8_t  magic[2];
    uint8_t  type;                          // OTA_MSG_OFFER
    uint8_t  flags;                         // OTA_OFFER_FLAG_*
    uint32_t image_size;
    uint16_t chunk_count;
    uint16_t chunk_size;
    uint8_t  md5[16];                       // of the whole image
    char     fw_version[OTA_VERSION_LEN];   // what is being offered
} ota_offer_t;

// 208 bytes, fixed even for a short final chunk so length-dispatch stays
// trivial; `len` says how much of data[] is real.
typedef struct __attribute__((packed)) {
    uint8_t  magic[2];
    uint8_t  type;                          // OTA_MSG_CHUNK
    uint8_t  reserved;
    uint16_t index;
    uint16_t len;
    uint8_t  data[OTA_CHUNK_DATA_MAX];
} ota_chunk_t;

// 10 bytes — deliberately not 8, which is sensor_v2_packet_t.
// next_index drives both retry and resume: the hub simply sends whatever
// the device asks for next, so a dropped chunk costs one round trip and a
// device that reboots mid-transfer resumes instead of restarting.
typedef struct __attribute__((packed)) {
    uint8_t  magic[2];
    uint8_t  type;                          // OTA_MSG_ACK | OTA_MSG_RESULT
    uint8_t  state;                         // OTA_STATE_*
    uint16_t next_index;
    uint8_t  progress_pct;
    uint8_t  error;                         // OTA_ERR_*
    uint8_t  reserved[2];
} ota_ack_t;

// ============================================================
// WIRE-FORMAT SIZE GUARDS
// Hub RX dispatch by length:
//   4  = channel_probe_t      (any device → hub)
//   5  = remote_packet_t      (remote → hub)
//   6  = display_request_t    (display → hub, v0.06+)
//   8  = sensor_v2_packet_t   (sensor → hub)
// Device RX dispatch by length:
//   3  = hub_response_t       (hub → any device)
//   20 = probe_response_t     (hub → any device, post-probe)
//   30 = display_state_t      (hub → display; 24 bytes in v0.06)
// If any struct changes size, dispatch silently misroutes packets —
// these asserts turn that into a build failure across all repos.
// ============================================================
#ifdef __cplusplus
static_assert(sizeof(channel_probe_t)   ==  4, "channel_probe_t must stay 4 bytes (hub RX length-dispatch)");
static_assert(sizeof(probe_response_t)  == 20, "probe_response_t must stay 20 bytes (device RX length-dispatch)");
static_assert(sizeof(hub_response_t)    ==  3, "hub_response_t must stay 3 bytes (device RX length-dispatch)");
static_assert(sizeof(remote_packet_t)    ==  5, "remote_packet_t must stay 5 bytes (hub RX length-dispatch)");
static_assert(sizeof(sensor_v2_packet_t) ==  8, "sensor_v2_packet_t must stay 8 bytes (hub RX length-dispatch)");
static_assert(sizeof(display_request_t)  ==  6, "display_request_t must stay 6 bytes (hub RX length-dispatch)");
static_assert(sizeof(display_state_t)    == 30, "display_state_t must stay 30 bytes (device RX length-dispatch)");
static_assert(sizeof(ota_request_t)      == 47, "ota_request_t must stay 47 bytes (hub RX length-dispatch)");
static_assert(sizeof(ota_offer_t)        == 44, "ota_offer_t must stay 44 bytes (device RX length-dispatch)");
static_assert(sizeof(ota_chunk_t)        == 208, "ota_chunk_t must stay 208 bytes (device RX length-dispatch)");
static_assert(sizeof(ota_ack_t)          == 10, "ota_ack_t must stay 10 bytes (hub RX length-dispatch)");

// Every dispatch length must be unique within its direction, or packets
// silently misroute. These catch a collision at build time in all repos.
static_assert(sizeof(ota_ack_t) != sizeof(sensor_v2_packet_t), "OTA ack collides with sensor packet");
static_assert(sizeof(ota_request_t) != sizeof(sensor_v2_packet_t), "OTA request collides with sensor packet");
static_assert(sizeof(ota_offer_t) != sizeof(display_state_t), "OTA offer collides with display state");
static_assert(sizeof(ota_offer_t) != sizeof(probe_response_t), "OTA offer collides with probe response");
static_assert(sizeof(ota_chunk_t) != sizeof(display_state_t), "OTA chunk collides with display state");
#endif

// ============================================================
// BATTERY THRESHOLDS
// ============================================================
#define BATT_PCT_LOW            20      // warn user
#define BATT_PCT_CRITICAL       10      // critical warning
#define BATT_PCT_LOCKOUT         5      // refuse to operate, protect cell
// Voltage floor read at no load. WiFi TX bursts (~150 mA peak) sag a tired
// LiPo 100–200 mV; 3.1 V gives ~100 mV margin above the ~2.7 V ESP32 BOR.
// R37/A4: costs only the bottom ~3% of usable capacity.
#define BATT_VOLTAGE_MIN       3.1f     // absolute minimum, never go below

// ============================================================
// WIFI CHANNEL RANGE
// All nodes scan channels WIFI_CHANNEL_MIN..WIFI_CHANNEL_MAX.
// DEFAULT_WIFI_CHANNEL is the channel nodes try first; set to
// match your hub's AP channel.
// ============================================================
#define DEFAULT_WIFI_CHANNEL     1
#define WIFI_CHANNEL_MIN         1
#define WIFI_CHANNEL_MAX        13
