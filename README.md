# remote-protocol

Shared ESP-NOW wire format **and shared client logic** for a boat's navigation
and sensor electronics. Consumed by every device in the fleet as a git submodule
at `protocol/`.

| Repo | Role |
|---|---|
| [petegale/esp_utility](https://github.com/petegale/esp_utility) | Hub — NMEA2000 gateway, history store, OTA server (local folder `sensor_hub`) |
| [petegale/sensor-node](https://github.com/petegale/sensor-node) | Wireless sensor nodes — tank, temperature, RPM |
| [petegale/sensor-display](https://github.com/petegale/sensor-display) | M5Paper e-paper gauge — battery, pull model |
| [petegale/waveshare-display](https://github.com/petegale/waveshare-display) | 4.3B touch LCD helm panel — mains, always on |
| [petegale/t5-display](https://github.com/petegale/t5-display) | LilyGo T5 e-paper — display that also acts as the remote |
| ~~petegale/remote~~ | Two-button fob — **retired Aug 2026** |

## What's here

| File | Contents |
|---|---|
| `remote_protocol.h` | Packet structs, message types, flags, version floors |
| `espnow_client.h` | The probe / pair / peer state machine, as pure logic |
| `espnow_signal.h` | Link-quality smoothing, hysteresis and bar packing, as pure logic |

**Not here:** project-local timing constants (`ESPNOW_ACK_TIMEOUT_MS`,
`CHANNEL_PROBE_LISTEN_MS`, `MAX_TX_RETRIES`, button debounce and hold timings).
Those live in each project's own `config.h` so they can be tuned independently
without touching the shared header.

### Why the client logic lives here too

Originally this repo held only the wire format. The client state machine was
hoisted in August 2026 because every device had reimplemented probe, pair and
peer management, and each had got the same subtleties wrong independently.

One bug class alone — an unencrypted probe response silently discarded because
the peer was still registered encrypted — surfaced three separate times in a
single session, on three different links. The sensor node had carried the fix
for months; the display was written without it, and nothing connected the two.

The header is deliberately free of Arduino dependencies and does no allocation,
so all of it is exercised by host tests in the consuming repos rather than only
on hardware.

## Packet dispatch is by length

The hub has one receive callback and routes on `len`. **Every size must stay
distinct**, which constrains how packets may grow:

| Bytes | Packet | Direction |
|---|---|---|
| 3 | `hub_response_t` | hub → device |
| 4 | `channel_probe_t` | device → hub (broadcast) |
| 5 | `remote_packet_t` | remote → hub |
| 6 | `display_request_t` | display → hub |
| 7 | `history_request_t` | display → hub |
| 8 | `sensor_v2_packet_t` | sensor → hub |
| 20 | `probe_response_t` | hub → device |
| 30 | `display_state_t` | hub → display |
| 216 | `history_response_t` | hub → display |

`static_assert` guards every size. A consequence worth knowing:
`sensor_v2_packet_t` has **no spare byte**, so it cannot be extended without
breaking every unmigrated node at once.

## Versioning: per-family floors, not one number

`PROTOCOL_VERSION` is a single constant, but checking every packet against it
would mean a change to display packets stranding every sensor on the boat. So
each packet family has its own floor:

```c
#define SENSOR_PACKET_MIN_VERSION   0x02  // unchanged since v0.02
#define REMOTE_PACKET_MIN_VERSION   0x02  // unchanged since v0.02
#define DISPLAY_PACKET_MIN_VERSION  0x07  // display packets grew a battery block
```

A sensor sending `0x04` is accepted by a `0x07` hub, because its packet has not
changed shape. Only display packets require a coordinated flash.

### Some messages are deliberately outside versioning entirely

The OTA and history message sets are **magic-keyed and never version-gated.**

For history that is a convenience. For OTA it is essential: if the update
trigger rode on a version-checked packet, a future bump that broke the link
would lock out the very mechanism needed to fix it — which is exactly what the
v0.07 display bump did, and what `test_protocol_compat` now guards against.

**Rule: every packet in the OTA exchange is magic-keyed.** The update path must
survive any future protocol change.

## Security model (v0.05 and later)

All unicast links use AES-128 CCMP with a per-link key (LMK) that the hub
generates during pairing and sends in the **probe response, in the clear**.
Physical proximity during a user-initiated 60-second pairing window is the
security model. `ESPNOW_PMK` must be set on every device.

The hub enforces a MAC allowlist: commands from unpaired remotes are dropped,
and sensor data from unconfigured MACs is dropped outside a pairing window.

**ESP-NOW allows six encrypted peers**, shared across sensors, displays and the
remote. That, not any table size in this header, is the fleet's real ceiling.

## Adding to a project

```bash
git submodule add https://github.com/petegale/remote-protocol protocol
```

Then in `platformio.ini`:

```ini
build_flags = -I protocol
```

Include as:

```c
#include "remote_protocol.h"
```

Clone consumers with `--recurse-submodules`, or the build fails on a missing
header.

## Updating

```bash
git submodule update --remote protocol
git add protocol
git commit -m "chore(protocol): bump remote-protocol submodule"
```

Consumers pin by commit, so they may sit on different pointers. That is fine as
long as the version floors above are respected — but a consumer running shared
*logic* from an older pointer is running code the current tests do not cover, so
prefer to keep them level.

## Protocol version history

| Version | Date | Change |
|---|---|---|
| `0x01` | Apr 2026 | Initial: `sensor_packet_t`, tank-only, 7 bytes |
| `0x02` | May 2026 | `sensor_v2_packet_t` (8 bytes) with a `sensor_type` discriminator; UDP `$XDR` transport removed from the hub |
| `0x03` | May 2026 | `device_id` renamed to `channel`; the hub routes by ESP-NOW sender MAC instead, removing the USB serial config step |
| `0x04` | Jun 2026 | Added `SENSOR_TYPE_TANK_RESISTIVE` (0x06) — raw 12-bit ADC counts, same packet shape |
| `0x05` | Jun 2026 | **Breaking.** AES-128 CCMP on all unicast links; `probe_response_t` (20 B) carrying the LMK; `hub_response_t` (3 B); MAC allowlist; user-initiated pairing mode |
| `0x06` | Jul 2026 | Added the display node class — `display_request_t` (6 B) and `display_state_t` (24 B). Additive; sensors and remotes unaffected |
| `0x07` | Jul 2026 | **Breaking for displays.** House-battery telemetry in `display_state_t` (24 → 30 B), forwarded from a Victron monitor on the hub's BLE listener |

Unversioned additions since, all magic-keyed:

| Added | Contents |
|---|---|
| Jul 2026 | OTA message set — `OTA_MSG_REQUEST` / `OFFER` / `CHUNK` / `ACK` / `RESULT`, plus `OTA_MSG_INFO` for unsolicited device self-announcement |
| Jul 2026 | History queries — `history_request_t` / `history_response_t`, resolved by metric name rather than positional index |
| Jul 2026 | Tank capacity carried in `display_state_t`'s reserved bytes, so displays can show a rate in litres per hour with no size change |
| Aug 2026 | `espnow_client.h` — shared client state machine, with per-device link-liveness and boot policy |
| Aug 2026 | `espnow_signal.h` — link quality as bars; `display_state_t.sensor_sig` packs two bits per slot into a previously-reserved byte, so there is no size change |
