# WiFi RSSI Motion Detector for M5Cardputer by imnoturbadboy

**Passive motion detection using Wi-Fi RSSI variance** - no dedicated sensors required. The M5Cardputer captures 802.11 data frames in promiscuous mode and analyzes Received Signal Strength Indicator (RSSI) fluctuations to detect human movement in the vicinity.

---

## How It Works

The firmware operates the ESP32-S3 in Wi-Fi promiscuous mode, capturing data frames from a selected access point. Instead of complex CSI extraction (which requires custom ESP-IDF builds), this implementation uses **RSSI (Received Signal Strength Indicator)** - a value natively provided by the Wi-Fi hardware in every received frame.

### The Physics Behind It

Human bodies are mostly water, which absorbs and reflects 2.4 GHz radio waves. When a person moves between an access point and the M5Cardputer:
- The signal path changes due to multipath reflections
- Signal strength fluctuates as body position alters wave interference patterns
- RSSI values show measurable variance above the ambient noise floor

### Signal Processing

1. **Promiscuous Capture** - All data frames from the selected AP are captured
2. **RSSI Extraction** - Hardware RSSI value (dBm) is read from `rx_ctrl.rssi`
3. **EMA Smoothing** - Exponential Moving Average (α = 0.15) reduces noise while preserving motion-induced fluctuations
4. **Baseline Calibration** - 150 samples establish ambient RSSI in a static environment
5. **Deviation Detection** - Real-time deviation from baseline = `|current_RSSI - baseline|`

---

## Features

### Core Detection
- **Passive operation** - no active transmissions, completely silent
- **AP Scanner** - Discovers nearby networks with RSSI, channel, encryption, and client counts
- **Calibration** - Establishes ambient RSSI baseline (requires network traffic)
- **Adjustable threshold** - Sensitivity from 1.0 to 30.0 dB deviation

### Visual Modes

| Mode | Description |
|------|-------------|
| Scan | AP discovery with client enumeration via channel hopping (1-13) |
| Monitor | Real-time display: EMA RSSI (dBm), baseline value, deviation, packet rate |
| Radar View | Polar visualization with estimated distance zones (<1m, 1-3m, >3m) |
| Debug | Packet counters, channel switching, calibration status, live metrics |
| Test | Waveform simulation for UI validation without live network |

### Distance Heuristics

Deviation-to-distance mapping (approximate, environment-dependent):

| Deviation | Estimated Distance |
|-----------|-------------------|
| ≤3 dB | 300-500 cm (far) |
| 3-6 dB | 150-300 cm (medium) |
| 6-10 dB | 70-150 cm (close) |
| 10-15 dB | 30-70 cm (very close) |
| >15 dB | 5-30 cm (immediate) |

---

## Hardware Requirements

| Component | Specification |
|-----------|---------------|
| Device | M5Cardputer |
| SoC | ESP32-S3 |
| Display | 240×135 TFT (M5GFX) |
| Input | Integrated QWERTY keyboard |
| Wi-Fi | 2.4 GHz 802.11 b/g/n |

---

## Software Dependencies

- **M5Cardputer Arduino Library** - Display, keyboard, and system functions

*All other dependencies (WiFi, esp_wifi, esp_wifi_types, vector, set, map, algorithm, cmath) are included with the ESP32 Arduino Core.*

---

## Installation

1. Install M5Cardputer library in Arduino IDE
2. Select board: M5Stack-Cardputer (ESP32-S3)
3. Upload the sketch
4. No additional hardware required

---

## Usage Guide

### Quick Start

1. Power on - Device boots to Scan mode
2. Press S - Scan for nearby access points
3. Navigate - Use Up/Down arrows to select an AP
4. Press Enter - Start calibration
5. Generate traffic - Stream video/download on target network during calibration
6. Monitor - Device auto-switches to Monitor mode after calibration

### Key Bindings

| Key | Action |
|-----|--------|
| S | Scan mode |
| M | Monitor mode |
| D | Debug mode |
| T | Test mode |
| G | Toggle Radar View |
| V | Cycle radar size (Small/Medium/Large) |
| H | Increase threshold (+) |
| L | Decrease threshold (-) |
| R | Recalibrate |
| F | Reset counters / deviation peak |
| B | Back / Cancel |
| Space | Toggle simulated movement (Test mode) |
| Up/Down | Navigate AP list |
| Enter | Select AP / Confirm |

### Debug Tab Navigation

- P - Packets tab (counters, RSSI, baseline)
- C - Channel tab (1-13 selection)
- A - Calibration tab (threshold, EMA settings)

---

## Technical Details

### RSSI Range

Typical values: -100 to -20 dBm

- less then -50 dBm → Excellent (green)
- equal -70 to -50 dBm → Good (yellow)
- more then -70 dBm → Weak (red)

### EMA Smoothing
current_amplitude = ALPHA * rssi + (1-ALPHA) * current_amplitude;
// ALPHA = 0.15

- Lower alpha = smoother output, slower response
- Higher alpha = more responsive, noisier output

### Calibration

- Frames collected: 150
- Timeout: 30 seconds
- Requires: Active traffic on target AP
- Result: Baseline RSSI value (average of collected samples)

### Packet Processing

- Only data frames (WIFI_PKT_DATA) are processed
- Frames are filtered by BSSID (selected AP)
- RSSI extracted from hardware RX control block
- Client sniffing captures associated station MACs

---

## Limitations

| Issue | Description |
|-------|-------------|
| Network traffic required | Detection quality depends on activity on the monitored AP |
| No hardware CSI | True CSI extraction requires custom ESP-IDF patches |
| Environmental sensitivity | Other 2.4 GHz interference affects baseline stability |
| Distance estimation | Heuristic mapping is approximate, not precise positioning |
| Client counting | Passive sniffing may miss some clients |

---

## Performance Notes

### Optimal Conditions
- AP with consistent background traffic (video streaming, file transfers)
- Room with minimal 2.4 GHz interference
- Calibration performed in static environment

### Detection Range
- Close range (<3m): Highly reliable
- Medium range (3-8m): Reliable with good traffic
- Long range (>8m): Limited sensitivity

### False Positives
- Other RF interference (microwave ovens, cordless phones)
- Sudden environmental changes (opening doors, moving furniture)
- AP channel switching or power saving

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No packets during calibration | Ensure target AP has active traffic |
| False positives | Increase threshold with H key |
| No detection when moving | Decrease threshold with L key |
| Empty AP list | Ensure Wi-Fi is enabled on nearby devices |
| Calibration timeout | Check AP is within range and has clients |
| Unstable baseline | Reduce RF noise, recalibrate multiple times |

---

## Author

**imnoturbadboy**

- GitHub: [@imnoturbadboy](https://github.com/imnoturbadboy)
- Telegram: [@trac3back](https://t.me/trac3back)

---
