# remote-protocol

Shared ESP-NOW wire-format header for the yacht electronics suite:

| Repo | Role |
|---|---|
| [petegale/esp_utility](https://github.com/petegale/esp_utility) | Sensor hub (WeAct CAN485 ESP32) |
| [petegale/remote](https://github.com/petegale/remote) | Autopilot remote (Beetle ESP32-C6) |
| [petegale/sensor-node](https://github.com/petegale/sensor-node) | Wireless sensor node (M5Stack Atom + DS1603L) |

## What's here

`remote_protocol.h` — protocol-level definitions shared by all three:

- `PROTOCOL_VERSION` — bump when packet structures change; all nodes must match
- `remote_packet_t` (5 bytes) — remote → hub button commands
- `channel_probe_t` (4 bytes) — channel-discovery handshake (broadcast + unicast reply)
- `sensor_v2_packet_t` (8 bytes) — sensor-node → hub readings (tank mm, temp centi-°C, RPM)
- `command_t`, `sensor_type_t` enums
- `FLAG_*` bits, battery thresholds, WiFi channel range

**Not here:** project-local timing constants (`ESPNOW_ACK_TIMEOUT_MS`, `CHANNEL_PROBE_LISTEN_MS`, `MAX_TX_RETRIES`, button debounce/chord/hold timings). Those live in each project's `config.h` so they can be tuned independently without touching the shared header.

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

## Updating

```bash
git submodule update --remote protocol
git add protocol
git commit -m "chore: bump remote-protocol submodule"
```

## Protocol version history

| Version | Date | Change |
|---|---|---|
| `0x01` | Apr 2026 | Initial: `sensor_packet_t` (tank-only, 7 bytes) |
| `0x02` | May 2026 | `sensor_v2_packet_t` (8 bytes) with `sensor_type` discriminator; UDP `$XDR` transport removed from hub |
