# WCMD for Arduino IDE
# WiFi CSI Motion Detector by imnoturbadboy

Passive motion detection for the M5Cardputer using Wi-Fi Channel State Information (CSI). The device operates in promiscuous mode, capturing 802.11 data frames from a selected access point and analyzing signal amplitude variance to infer human movement - without any dedicated sensors.

---

## How It Works

The firmware captures raw Wi-Fi frames via the ESP32 promiscuous API and extracts payload bytes that approximate CSI energy. During a calibration phase, a baseline amplitude is established from ambient network traffic. After calibration, real-time deviation from this baseline is used as a movement indicator: human bodies attenuate and reflect 2.4 GHz signals, causing measurable amplitude fluctuations.

This approach does not use the ESP32's hardware CSI extraction (`esp_wifi_set_csi()`), but instead derives a scalar energy proxy from frame payloads - making it compatible with standard ESP-IDF Wi-Fi builds without custom patches.

---

## Features

- **AP Scanner** - discovers nearby access points with RSSI, channel, encryption type, and estimated client count (via passive client sniffing across channels 1–13)
- **Monitor Mode** - real-time amplitude and deviation display for a selected AP
- **Radar View** - visual representation of detected motion with distance estimation zones (<1 m / 1–3 m / >3 m) and adjustable radar size
- **Debug Mode** - packet counters, per-second rate, channel switching (1–13), baseline readout, live deviation
- **Test Mode** - simulated waveform for UI and threshold validation without a live network
- **Adjustable threshold** - configurable sensitivity (1.0–30.0) for different environments
- **Client counting** - passive enumeration of associated stations per BSSID

---

## Hardware

| Component | Details |
|---|---|
| Device | M5Cardputer |
| SoC | ESP32-S3 |
| Display | 240×135 TFT via M5GFX |
| Input | Built-in keyboard |

---

## Dependencies

- [M5Cardputer Arduino Library](https://github.com/m5stack/M5Cardputer)
- ESP-IDF Wi-Fi components (bundled with ESP32 Arduino core)
- Standard C++ STL (`vector`, `set`, `map`)

---

## Usage

### 1. Scan

Press `S` to scan for nearby APs. The scanner collects networks and passively counts associated clients by hopping channels. Results are sorted by RSSI.

### 2. Select AP and Calibrate

Navigate the AP list with `↑`/`↓`, then press `Enter` to start calibration. During calibration, the device collects ~150 amplitude samples from the selected network. **Generate continuous traffic on that network** (video streaming, large download) to improve baseline quality. Calibration completes automatically or can be cancelled with `B`.

### 3. Monitor

After successful calibration, the device enters Monitor Mode automatically. Amplitude deviation from the baseline is displayed in real time. Motion events are flagged when deviation exceeds the configured threshold.

### 4. Radar View

Press `G` to toggle the radar overlay (requires prior calibration). Press `V` to cycle radar size (S / M / L). Threshold can be adjusted with `H` (increase) and `L` (decrease).

---

## Key Bindings

| Key | Action |
|---|---|
| `S` | Scan mode |
| `M` | Monitor mode |
| `D` | Debug mode |
| `T` | Test mode |
| `G` | Toggle radar view |
| `V` | Cycle radar size |
| `H` / `L` | Increase / decrease threshold |
| `R` | Recalibrate |
| `F` | Reset counters / peak |
| `B` | Back / cancel |
| `Space` | Toggle simulated movement (Test mode) |

---

## Limitations

- Requires active network traffic on the monitored AP - detection quality degrades on low-activity networks
- Amplitude-based CSI proxy is less precise than hardware CSI; environmental RF noise affects baseline stability
- Distance estimation in radar view is heuristic and not geometrically accurate
- Client counting is approximate some clients may be missed depending on traffic volume during the scan window

---

## Author

[imnoturbadboy] | (https://github.com/imnoturbadboy) | (t.me/trac3back)
