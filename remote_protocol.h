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
 */

#include <stdint.h>

// ============================================================
// PROTOCOL VERSION
// Increment when packet structures change. All nodes on the
// same network must use the same version.
// ============================================================
#define PROTOCOL_VERSION        0x04

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
// FLAG BITS (remote_packet_t.flags and sensor_v2_packet_t.flags)
// ============================================================
#define FLAG_BATT_LOW           0x01    // battery <= 20%
#define FLAG_BATT_CRITICAL      0x02    // battery <= 10%
#define FLAG_TX_RETRY           0x04    // this is a retry attempt
#define FLAG_CHANNEL_CHANGED    0x08    // remote had to rescan for channel

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
// CHANNEL PROBE PACKET (broadcast during channel scan)
// 4 bytes. Remote broadcasts on each channel; hub responds
// on its current channel.
// ============================================================
typedef struct __attribute__((packed)) {
    uint8_t     magic[2];           // PROBE_MAGIC_0, PROBE_MAGIC_1
    uint8_t     type;               // PROBE_TYPE_REQUEST or PROBE_TYPE_RESPONSE
    uint8_t     channel;            // 0 in request; hub's channel in response
} channel_probe_t;

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
// WIRE-FORMAT SIZE GUARDS
// The hub's ESP-NOW RX callback dispatches purely by packet length
// (4 = probe, 5 = remote, 8 = sensor). If any struct changes size —
// a reordered field, a wider type, or padding creeping in despite the
// packed attribute — that dispatch silently misroutes packets with no
// compile error in the consuming firmware. These asserts turn such a
// regression into a build failure in all three repos at once.
// ============================================================
#ifdef __cplusplus
static_assert(sizeof(channel_probe_t)   == 4, "channel_probe_t must stay 4 bytes (hub length-dispatch)");
static_assert(sizeof(remote_packet_t)    == 5, "remote_packet_t must stay 5 bytes (hub length-dispatch)");
static_assert(sizeof(sensor_v2_packet_t) == 8, "sensor_v2_packet_t must stay 8 bytes (hub length-dispatch)");
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
