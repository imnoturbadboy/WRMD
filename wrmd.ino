/*
 * WiFi RSSI Motion Detector by imnoturbadboy
 */

#include "M5Cardputer.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <vector>
#include <algorithm>
#include <cmath>
#include <set>
#include <map>

typedef struct {
    uint16_t protocol:2;
    uint16_t type:2;
    uint16_t subtype:4;
    uint16_t to_ds:1;
    uint16_t from_ds:1;
    uint16_t more_frag:1;
    uint16_t retry:1;
    uint16_t pwr_mngt:1;
    uint16_t more_data:1;
    uint16_t wep:1;
    uint16_t order:1;
} wifi_frame_ctrl_t;

typedef struct {
    wifi_frame_ctrl_t frame_ctrl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} wifi_mac_header_t;

void promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type);
void flushClientBuffer();
void updateTestSimulation();
void processRealData();

struct AccessPoint {
    String ssid;
    String bssid_str;
    uint8_t bssid[6];
    int32_t rssi;
    uint8_t channel;
    bool encrypted;
    int client_count;
};

struct RadarPoint {
    float angle;
    float distance;
    float strength;
    unsigned long timestamp;
};

struct GraphPoint {
    float deviation;
    unsigned long timestamp;
};

enum AppMode { MODE_SCAN, MODE_MONITOR, MODE_DEBUG, MODE_TEST };
AppMode current_mode = MODE_SCAN;
AppMode last_drawn_mode = MODE_SCAN;

enum ScanState { SCAN_IDLE, SCANNING, SCAN_LIST };
ScanState scan_state = SCAN_IDLE;

enum DebugTab { DEBUG_PACKETS, DEBUG_CHANNEL, DEBUG_CALIBRATE };
DebugTab debug_tab = DEBUG_PACKETS;

enum RadarSize { RADAR_SMALL, RADAR_MEDIUM, RADAR_LARGE };
RadarSize radar_size = RADAR_MEDIUM;

std::vector<AccessPoint> ap_list;
int selected_ap = 0, list_offset = 0;
const int items_per_page = 7;
uint8_t current_channel = 6;
float movement_threshold = 5.0;
const int calibration_frames = 150;

volatile float current_amplitude = 0;
volatile bool new_data_available = false;
volatile unsigned long last_packet_time = 0;

static const float EMA_ALPHA = 0.15f;
static bool ema_initialized = false;

float csi_baseline = 0;
bool is_calibrated = false;
int calibration_count = 0;
float calib_sum = 0;

volatile unsigned long packet_count_total = 0;
unsigned long packet_count_snapshot = 0;
unsigned long last_packet_report = 0;

int movement_counter = 0;
unsigned long last_movement_time = 0;
float deviation_peak = 0;
unsigned long peak_reset_time = 0;
float current_deviation = 0;

std::vector<GraphPoint> graph_points;
const int max_graph_points = 50;
unsigned long last_graph_add = 0;

std::vector<RadarPoint> radar_points;
const int max_radar_points = 30;
bool radar_view_active = false;
unsigned long last_radar_update = 0;
float last_known_deviation = 0;
unsigned long last_deviation_time = 0;

struct ClientRecord {
    uint8_t bssid[6];
    uint8_t client[6];
};
const int CLIENT_BUF_SIZE = 256;
ClientRecord client_buf[CLIENT_BUF_SIZE];
volatile int client_buf_head = 0;
int client_buf_tail = 0;
std::map<String, std::set<String>> ap_clients;
volatile bool client_sniffing_active = false;

float test_simulated_deviation = 0;
unsigned long test_last_update = 0;
float test_phase = 0;
bool test_movement_active = false;

unsigned long last_key_time = 0;
bool key_repeat_lock = false;

bool is_monitoring_real = false;
bool calibration_mode = false;
uint8_t calibration_channel = 6;
uint8_t calibration_bssid[6];
bool calibration_filter_ap = false;

bool isBroadcastOrMulticast(const uint8_t* mac) {
    bool is_broadcast = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0xFF) { is_broadcast = false; break; }
    }
    if (is_broadcast) return true;
    if (mac[0] & 0x01) return true;
    return false;
}

bool isValidClientMAC(const uint8_t* mac) {
    bool all_zero = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) return false;
    if (isBroadcastOrMulticast(mac)) return false;
    return true;
}

String macToString(const uint8_t* mac) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(mac_str);
}

static inline bool IRAM_ATTR macEqual(const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
    return true;
}

float deviationToDistance(float deviation) {
    if (deviation <= 3) return random(300, 500);
    if (deviation <= 6) return random(150, 300);
    if (deviation <= 10) return random(70, 150);
    if (deviation <= 15) return random(30, 70);
    return random(5, 30);
}

void getRadarSizeParams(int &center_x, int &center_y, int &radius_near, int &radius_mid, int &radius_far) {
    switch(radar_size) {
        case RADAR_SMALL:  center_x=120; center_y=75; radius_near=20; radius_mid=40; radius_far=55; break;
        case RADAR_MEDIUM: center_x=120; center_y=75; radius_near=25; radius_mid=55; radius_far=75; break;
        case RADAR_LARGE:  center_x=120; center_y=75; radius_near=35; radius_mid=70; radius_far=90; break;
    }
}

void updateRadarFromDeviation(float deviation, unsigned long timestamp) {
    if (!radar_view_active) return;
    if (deviation > 1.0) { last_known_deviation = deviation; last_deviation_time = timestamp; }
    if (timestamp - last_radar_update > 300) {
        if (deviation > movement_threshold * 0.6) {
            RadarPoint point;
            point.angle = (float)(random(-80, 80));
            point.distance = deviationToDistance(deviation);
            point.strength = constrain((deviation / movement_threshold) * 100, 20, 100);
            point.timestamp = timestamp;
            radar_points.push_back(point);
            while (radar_points.size() > max_radar_points)
                radar_points.erase(radar_points.begin());
        }
        last_radar_update = timestamp;
    }
    for (int i = 0; i < (int)radar_points.size(); i++) {
        if (timestamp - radar_points[i].timestamp > 10000) {
            radar_points.erase(radar_points.begin() + i);
            i--;
        }
    }
}

void drawRadarView() {
    if (!radar_view_active) return;
    M5Cardputer.Display.fillScreen(BLACK);
    int center_x, center_y, radius_near, radius_mid, radius_far;
    getRadarSizeParams(center_x, center_y, radius_near, radius_mid, radius_far);

    M5Cardputer.Display.setTextColor(WHITE);
    char threshold_text[32];
    snprintf(threshold_text, sizeof(threshold_text), "Thr:%.1f", movement_threshold);
    M5Cardputer.Display.drawString(threshold_text, 5, 5);

    uint16_t threshold_color = (movement_threshold < 4) ? GREEN : (movement_threshold < 7 ? YELLOW : RED);
    M5Cardputer.Display.fillRect(5, 18, 40, 4, threshold_color);

    String size_text = (radar_size == RADAR_SMALL) ? "S" : (radar_size == RADAR_MEDIUM ? "M" : "L");
    M5Cardputer.Display.drawString(size_text, 50, 5);

    char dev_text[32];
    snprintf(dev_text, sizeof(dev_text), "Dev:%.1f", current_deviation);
    M5Cardputer.Display.drawString(dev_text, 160, 5);

    M5Cardputer.Display.drawCircle(center_x, center_y, radius_far, 0x39E7);
    M5Cardputer.Display.setTextColor(0x39E7);
    M5Cardputer.Display.drawString(">3m", center_x + radius_far - 18, center_y - 5);
    M5Cardputer.Display.drawCircle(center_x, center_y, radius_mid, 0x39E7);
    M5Cardputer.Display.drawString("1-3m", center_x + radius_mid - 16, center_y - 5);
    M5Cardputer.Display.drawCircle(center_x, center_y, radius_near, 0x39E7);
    M5Cardputer.Display.drawString("<1m", center_x + radius_near - 13, center_y - 5);

    for (int angle = -90; angle <= 90; angle += 45) {
        float rad = angle * 3.14159 / 180.0;
        int x2 = center_x + cos(rad) * radius_far;
        int y2 = center_y + sin(rad) * radius_far;
        M5Cardputer.Display.drawLine(center_x, center_y, x2, y2, 0x39E7);
        String dir = (angle==-90)?"L":(angle==-45)?"FL":(angle==0)?"F":(angle==45)?"FR":"R";
        M5Cardputer.Display.drawString(dir, x2 - 5, y2 - 8);
    }

    M5Cardputer.Display.fillCircle(center_x, center_y, 7, BLUE);
    M5Cardputer.Display.fillCircle(center_x, center_y, 4, CYAN);
    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("YOU", center_x - 12, center_y - 4);

    for (const auto& point : radar_points) {
        float rad = point.angle * 3.14159 / 180.0;
        int radius_px;
        if (point.distance <= 100)       radius_px = map(point.distance, 0, 100, 5, radius_near);
        else if (point.distance <= 300)  radius_px = map(point.distance, 100, 300, radius_near, radius_mid);
        else                             radius_px = map(constrain(point.distance, 300, 500), 300, 500, radius_mid, radius_far);

        int x = center_x + cos(rad) * radius_px;
        int y = center_y + sin(rad) * radius_px;

        uint16_t color = (point.distance < 100 || point.strength > 70) ? RED :
                         (point.distance < 300 || point.strength > 40)  ? YELLOW : GREEN;
        int size = (point.distance < 100) ? map(point.strength, 0, 100, 4, 8) :
                   (point.distance < 300) ? map(point.strength, 0, 100, 3, 6) :
                                            map(point.strength, 0, 100, 2, 4);
        M5Cardputer.Display.fillCircle(x, y, size, color);
        if (millis() - point.timestamp < 500)
            M5Cardputer.Display.drawCircle(x, y, size + 2, color);
        if (point.distance < 100) {
            char dist_str[8];
            snprintf(dist_str, sizeof(dist_str), "%dcm", (int)point.distance);
            M5Cardputer.Display.setTextColor(WHITE);
            M5Cardputer.Display.drawString(dist_str, x - 15, y - 8);
        }
    }

    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawFastHLine(0, 170, 240, 0x7BEF);
    char info[64];
    snprintf(info, sizeof(info), "Pts:%d  ", (int)radar_points.size());
    M5Cardputer.Display.drawString(info, 5, 175);
    if (current_deviation > movement_threshold) {
        M5Cardputer.Display.fillRect(70, 175, 50, 12, RED);
        M5Cardputer.Display.setTextColor(BLACK);
        M5Cardputer.Display.drawString("MOVING!", 75, 176);
        M5Cardputer.Display.setTextColor(WHITE);
    } else {
        M5Cardputer.Display.drawString("---", 75, 176);
    }
    M5Cardputer.Display.drawString("G:exit V:size H/L:thr", 130, 175);

    bool very_close = false;
    for (const auto& point : radar_points)
        if (point.distance < 50 && point.strength > 70) { very_close = true; break; }
    if (very_close) {
        M5Cardputer.Display.fillRect(0, 0, 240, 20, RED);
        M5Cardputer.Display.setTextColor(WHITE);
        M5Cardputer.Display.drawString("  WARNING: PERSON VERY CLOSE! <50cm", 15, 5);
    }
}


void IRAM_ATTR promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;

    packet_count_total++;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < sizeof(wifi_mac_header_t)) return;

    uint8_t src_mac[6], dst_mac[6], bssid_mac[6];
    wifi_mac_header_t *header = (wifi_mac_header_t *)payload;

    if (header->frame_ctrl.to_ds && !header->frame_ctrl.from_ds) {
        memcpy(src_mac, header->addr2, 6);
        memcpy(dst_mac, header->addr1, 6);
        memcpy(bssid_mac, header->addr3, 6);
    } else if (!header->frame_ctrl.to_ds && header->frame_ctrl.from_ds) {
        memcpy(src_mac, header->addr3, 6);
        memcpy(dst_mac, header->addr1, 6);
        memcpy(bssid_mac, header->addr2, 6);
    } else {
        memcpy(src_mac, header->addr2, 6);
        memcpy(dst_mac, header->addr1, 6);
        memcpy(bssid_mac, header->addr3, 6);
    }

    if (client_sniffing_active) {
        if (isValidClientMAC(src_mac) && !macEqual(src_mac, bssid_mac)) {
            int next = (client_buf_head + 1) % CLIENT_BUF_SIZE;
            if (next != client_buf_tail) {
                memcpy(client_buf[client_buf_head].bssid, bssid_mac, 6);
                memcpy(client_buf[client_buf_head].client, src_mac, 6);
                client_buf_head = next;
            }
        }
        if (!header->frame_ctrl.to_ds && isValidClientMAC(dst_mac) && !macEqual(dst_mac, bssid_mac)) {
            int next = (client_buf_head + 1) % CLIENT_BUF_SIZE;
            if (next != client_buf_tail) {
                memcpy(client_buf[client_buf_head].bssid, bssid_mac, 6);
                memcpy(client_buf[client_buf_head].client, dst_mac, 6);
                client_buf_head = next;
            }
        }
    }

    bool accept_packet = false;
    if (calibration_mode) {
        accept_packet = true;
    } else if (is_monitoring_real && !ap_list.empty() && selected_ap < (int)ap_list.size()) {
        accept_packet = macEqual(bssid_mac, ap_list[selected_ap].bssid);
    } else if (!is_monitoring_real && !calibration_mode) {
        accept_packet = true;
    }

    if (accept_packet) {
        float rssi = (float)pkt->rx_ctrl.rssi;

        if (!ema_initialized) {
            current_amplitude = rssi;
            ema_initialized = true;
        } else {
            current_amplitude = EMA_ALPHA * rssi + (1.0f - EMA_ALPHA) * current_amplitude;
        }

        new_data_available = true;
        last_packet_time = millis();
    }
}

void flushClientBuffer() {
    while (client_buf_tail != client_buf_head) {
        ClientRecord &rec = client_buf[client_buf_tail];
        String bssid_str = macToString(rec.bssid);
        String client_str = macToString(rec.client);
        ap_clients[bssid_str].insert(client_str);
        client_buf_tail = (client_buf_tail + 1) % CLIENT_BUF_SIZE;
    }
}

void processRealData() {
    if (!new_data_available) return;

    noInterrupts();
    float amp = current_amplitude;
    new_data_available = false;
    interrupts();

    if (is_calibrated) {
        current_deviation = fabsf(amp - csi_baseline);

        if (current_deviation > deviation_peak)
            deviation_peak = current_deviation;

        if (current_deviation > movement_threshold) {
            last_movement_time = millis();
            movement_counter++;
        }

        if (radar_view_active)
            updateRadarFromDeviation(current_deviation, millis());
    }
}

bool initPassiveCSI(uint8_t channel, bool for_calibration = false) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    WiFi.mode(WIFI_MODE_NULL);
    delay(100);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    if (esp_wifi_start() != ESP_OK) return false;
    if (esp_wifi_set_promiscuous(true) != ESP_OK) return false;

    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);

    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filter);

    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;

    current_channel = channel;
    packet_count_total = 0;
    client_buf_head = 0;
    client_buf_tail = 0;
    ema_initialized = false;

    if (for_calibration) {
        calibration_mode = true;
        is_monitoring_real = false;
        is_calibrated = false;
        calibration_count = 0;
        calib_sum = 0;
        deviation_peak = 0;
        movement_counter = 0;
        radar_points.clear();
        graph_points.clear();
    } else {
        calibration_mode = false;
        is_monitoring_real = true;
    }

    delay(200);
    return true;
}

bool isSinglePress() {
    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
        if (!key_repeat_lock) {
            key_repeat_lock = true;
            last_key_time = millis();
            return true;
        }
    }
    if (key_repeat_lock && millis() - last_key_time > 300)
        key_repeat_lock = false;
    return false;
}

void switchMode(AppMode new_mode) {
    current_mode = new_mode;
    last_drawn_mode = (AppMode)-1;
    key_repeat_lock = true;
    last_key_time = millis();
    if (new_mode != MODE_TEST) radar_view_active = false;
    delay(150);
}

void updateTestSimulation() {
    if (millis() - test_last_update > 100) {
        test_phase += 0.1;
        float noise = random(-10, 10) / 10.0;
        test_simulated_deviation = test_movement_active ?
            abs(sin(test_phase) * 8.0 + noise + 2.0) :
            abs(noise * 0.3);

        packet_count_snapshot = random(50, 150);

        if (is_calibrated) {
            float dev = test_simulated_deviation;
            if (dev > deviation_peak) deviation_peak = dev;
            if (dev > movement_threshold) { last_movement_time = millis(); movement_counter++; }
            if (radar_view_active) updateRadarFromDeviation(dev, millis());
        }
        test_last_update = millis();
    }
}

void scanWiFi() {
    ap_list.clear();
    ap_clients.clear();
    scan_state = SCANNING;
    is_monitoring_real = false;
    calibration_mode = false;
    radar_view_active = false;

    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("Scanning APs...", 30, 40);

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    WiFi.mode(WIFI_STA);
    delay(100);

    int n = WiFi.scanNetworks(false, true, false, 500);

    if (n <= 0) {
        M5Cardputer.Display.fillScreen(BLACK);
        M5Cardputer.Display.drawString("No networks found!", 20, 50);
        delay(1500);
        scan_state = SCAN_IDLE;
        return;
    }

    for (int i = 0; i < n; i++) {
        AccessPoint ap;
        ap.ssid = WiFi.SSID(i);
        ap.rssi = WiFi.RSSI(i);
        ap.channel = WiFi.channel(i);
        ap.encrypted = (WiFi.encryptionType(i) != WIFI_AUTH_OPEN);
        ap.client_count = 0;
        if (ap.channel > 14) continue;
        memcpy(ap.bssid, WiFi.BSSID(i), 6);
        ap.bssid_str = macToString(ap.bssid);
        ap_list.push_back(ap);
    }

    std::sort(ap_list.begin(), ap_list.end(),
              [](const AccessPoint &a, const AccessPoint &b) { return a.rssi > b.rssi; });

    std::vector<AccessPoint> unique;
    for (auto &ap : ap_list) {
        bool dup = false;
        for (auto &u : unique) if (ap.bssid_str == u.bssid_str) { dup = true; break; }
        if (!dup) unique.push_back(ap);
    }
    ap_list = unique;

    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.drawString("Counting clients...", 20, 30);

    esp_wifi_stop();
    WiFi.mode(WIFI_MODE_NULL);
    delay(100);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);

    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);

    client_sniffing_active = true;

    for (int ch = 1; ch <= 13; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        char buf[32];
        snprintf(buf, sizeof(buf), "Channel %d/13", ch);
        M5Cardputer.Display.fillRect(0, 70, 240, 20, BLACK);
        M5Cardputer.Display.drawString(buf, 60, 70);
        unsigned long ch_start = millis();
        while (millis() - ch_start < 600) { flushClientBuffer(); delay(50); }
    }

    client_sniffing_active = false;
    flushClientBuffer();

    for (auto &ap : ap_list) {
        auto it = ap_clients.find(ap.bssid_str);
        if (it != ap_clients.end()) {
            it->second.erase(ap.bssid_str);
            ap.client_count = (int)it->second.size();
        } else {
            ap.client_count = 0;
        }
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();

    list_offset = 0;
    selected_ap = 0;
    scan_state = SCAN_LIST;

    M5Cardputer.Display.fillScreen(BLACK);
    int total_clients = 0;
    for (auto &ap : ap_list) total_clients += ap.client_count;
    char buf[64];
    snprintf(buf, sizeof(buf), "Found %d APs, %d clients", (int)ap_list.size(), total_clients);
    M5Cardputer.Display.drawString(buf, 10, 40);
    M5Cardputer.Display.drawString("Scan complete!", 30, 60);
    delay(2000);
}

void calibrate() {
    if (ap_list.empty() || selected_ap >= (int)ap_list.size()) {
        M5Cardputer.Display.fillScreen(BLACK);
        M5Cardputer.Display.drawString("No AP selected!", 30, 50);
        delay(1500);
        return;
    }

    calibration_count = 0;
    calib_sum = 0;
    is_calibrated = false;
    current_deviation = 0;
    current_amplitude = 0;
    ema_initialized = false;

    uint8_t target_channel = ap_list[selected_ap].channel;

    if (!initPassiveCSI(target_channel, true)) {
        M5Cardputer.Display.fillScreen(BLACK);
        M5Cardputer.Display.drawString("WiFi init failed!", 30, 50);
        delay(1500);
        return;
    }

    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("CALIBRATING...", 20, 25);
    M5Cardputer.Display.drawString("Channel: " + String(target_channel), 20, 45);
    M5Cardputer.Display.drawString("AP: " + ap_list[selected_ap].ssid.substring(0, 20), 20, 65);
    M5Cardputer.Display.drawString("Stand still, no movement!", 15, 85);
    M5Cardputer.Display.drawString("Collecting RSSI baseline...", 10, 105);
    M5Cardputer.Display.drawString("B to cancel", 55, 140);

    unsigned long start = millis();
    unsigned long last_update = 0;
    unsigned long last_packet_check = millis();
    int timeout_seconds = 30;

    while (calibration_count < calibration_frames) {
        M5Cardputer.update();

        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed() &&
            (M5Cardputer.Keyboard.isKeyPressed('b') || M5Cardputer.Keyboard.isKeyPressed('B'))) {
            M5Cardputer.Display.fillScreen(BLACK);
            M5Cardputer.Display.drawString("Calibration cancelled", 30, 50);
            delay(800);
            esp_wifi_set_promiscuous(false);
            return;
        }

        if (new_data_available) {
            noInterrupts();
            float amp = current_amplitude;
            new_data_available = false;
            interrupts();
            if (amp < -10.0f && amp > -110.0f) {
                calib_sum += amp;
                calibration_count++;
                last_packet_check = millis();
            }

            if (calibration_count % 5 == 0 || millis() - last_update > 500) {
                last_update = millis();
                M5Cardputer.Display.fillRect(0, 20, 240, 130, BLACK);
                M5Cardputer.Display.drawString("CALIBRATING...", 20, 25);
                M5Cardputer.Display.drawString("Channel: " + String(target_channel), 20, 45);

                int bar = (calibration_count * 200) / calibration_frames;
                M5Cardputer.Display.fillRect(10, 63, bar, 15, GREEN);
                M5Cardputer.Display.drawRect(10, 63, 200, 15, WHITE);

                char buf[64];
                snprintf(buf, sizeof(buf), "%d / %d", calibration_count, calibration_frames);
                M5Cardputer.Display.drawString(buf, 30, 85);
                snprintf(buf, sizeof(buf), "RSSI: %.1f dBm", amp);
                M5Cardputer.Display.drawString(buf, 30, 105);
                snprintf(buf, sizeof(buf), "Pkts: %lu", packet_count_total);
                M5Cardputer.Display.drawString(buf, 30, 125);
                M5Cardputer.Display.drawString("B to cancel", 55, 145);
            }
        }

        if (millis() - last_packet_check > 5000 && calibration_count > 0) {
            M5Cardputer.Display.fillRect(0, 20, 240, 130, BLACK);
            M5Cardputer.Display.drawString("No packets received!", 30, 50);
            M5Cardputer.Display.drawString("Check network activity", 20, 70);
            delay(2000);
            break;
        }

        if (millis() - start > timeout_seconds * 1000) {
            M5Cardputer.Display.fillScreen(BLACK);
            M5Cardputer.Display.drawString("Timeout!", 50, 40);
            M5Cardputer.Display.drawString("No WiFi data received", 20, 60);
            M5Cardputer.Display.drawString("Check if network is active", 15, 80);
            delay(2000);
            break;
        }

        delay(5);
    }

    esp_wifi_set_promiscuous(false);

    if (calibration_count > 10) {
        csi_baseline = calib_sum / calibration_count;
        is_calibrated = true;
    }

    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.drawString(is_calibrated ? "Calibration OK!" : "Calibration failed!", 20, 45);

    if (is_calibrated) {
        char buf[48];
        snprintf(buf, sizeof(buf), "Baseline: %.1f dBm", csi_baseline);
        M5Cardputer.Display.drawString(buf, 30, 65);
        snprintf(buf, sizeof(buf), "Samples: %d", calibration_count);
        M5Cardputer.Display.drawString(buf, 40, 85);
    } else {
        M5Cardputer.Display.drawString("Try a different AP", 30, 65);
        M5Cardputer.Display.drawString("or wait for more traffic", 20, 85);
    }

    delay(2000);

    if (is_calibrated && current_mode != MODE_TEST) {
        initPassiveCSI(target_channel, false);
        current_mode = MODE_MONITOR;
        last_drawn_mode = (AppMode)-1;
    }
}

void drawScanScreen() {
    if (last_drawn_mode != MODE_SCAN) {
        M5Cardputer.Display.fillScreen(BLACK);
        last_drawn_mode = MODE_SCAN;
    }

    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("SELECT MODE", 5, 3);
    M5Cardputer.Display.drawFastHLine(0, 18, 240, WHITE);

    if (radar_view_active && is_calibrated) { drawRadarView(); return; }

    if (scan_state == SCAN_IDLE) {
        M5Cardputer.Display.fillRect(0, 35, 240, 100, BLACK);
        M5Cardputer.Display.drawString("S:scan M:mon D:dbg T:test", 10, 50);
        M5Cardputer.Display.drawString("G:radar V:size", 10, 70);
        return;
    }

    if (scan_state == SCANNING) {
        M5Cardputer.Display.fillRect(0, 35, 240, 100, BLACK);
        M5Cardputer.Display.drawString("Scanning...", 30, 50);
        return;
    }

    M5Cardputer.Display.fillRect(0, 20, 240, 130, BLACK);
    M5Cardputer.Display.drawString("Select AP [" + String(list_offset+1) + "-" +
        String(min(list_offset+items_per_page, (int)ap_list.size())) + "/" + String(ap_list.size()) + "]", 5, 21);
    M5Cardputer.Display.drawFastHLine(0, 36, 240, 0x7BEF);
    M5Cardputer.Display.drawString("CH RSSI CL SSID", 5, 39);

    int y = 56;
    for (int i = list_offset; i < min(list_offset+items_per_page, (int)ap_list.size()); i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%2d %4d %2d ", ap_list[i].channel, ap_list[i].rssi, ap_list[i].client_count);
        String ssid = ap_list[i].ssid.substring(0, 13);
        M5Cardputer.Display.setTextColor(ap_list[i].rssi > -50 ? GREEN : (ap_list[i].rssi > -70 ? YELLOW : RED));
        if (i == selected_ap) M5Cardputer.Display.fillRect(0, y-2, 240, 16, 0x2104);
        M5Cardputer.Display.drawString(String(buf) + ssid, 5, y);
        M5Cardputer.Display.setTextColor(WHITE);
        y += 16;
    }

    M5Cardputer.Display.fillRect(0, 148, 240, 32, BLACK);
    M5Cardputer.Display.drawFastHLine(0, 148, 240, 0x7BEF);
    M5Cardputer.Display.drawString("^v:nav ENT:sel B:back G:radar V:size", 5, 152);
}

void drawMonitorScreen() {
    if (last_drawn_mode != MODE_MONITOR) {
        M5Cardputer.Display.fillScreen(BLACK);
        last_drawn_mode = MODE_MONITOR;
    }

    processRealData();

    if (radar_view_active && is_calibrated) { drawRadarView(); return; }

    M5Cardputer.Display.fillRect(0, 0, 240, 180, BLACK);
    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("MONITOR MODE", 5, 2);
    M5Cardputer.Display.drawFastHLine(0, 15, 240, WHITE);

    if (!ap_list.empty() && selected_ap < (int)ap_list.size()) {
        int y = 30;
        M5Cardputer.Display.drawString("AP: " + ap_list[selected_ap].ssid.substring(0, 20), 5, y); y += 16;
        M5Cardputer.Display.drawString("Ch: " + String(ap_list[selected_ap].channel) +
                                      " RSSI: " + String(ap_list[selected_ap].rssi) +
                                      " CL: " + String(ap_list[selected_ap].client_count), 5, y); y += 20;

        char buf[48];
        snprintf(buf, sizeof(buf), "Pkts: %lu", packet_count_snapshot);
        M5Cardputer.Display.drawString(buf, 5, y); y += 16;

        snprintf(buf, sizeof(buf), "RSSI(EMA): %.1f dBm", current_amplitude);
        M5Cardputer.Display.drawString(buf, 5, y); y += 16;

        if (is_calibrated) {
            snprintf(buf, sizeof(buf), "Base: %.1f dBm", csi_baseline);
            M5Cardputer.Display.drawString(buf, 5, y); y += 16;
            snprintf(buf, sizeof(buf), "Dev: %.2f", current_deviation);
            M5Cardputer.Display.drawString(buf, 5, y); y += 16;
            snprintf(buf, sizeof(buf), "Peak: %.2f", deviation_peak);
            M5Cardputer.Display.drawString(buf, 5, y); y += 16;
        }

        M5Cardputer.Display.drawFastHLine(0, y, 240, 0x7BEF); y += 5;

        for (int i = 0; i < min((int)ap_list.size(), 4); i++) {
            if (i == selected_ap) continue;
            String ssid = ap_list[i].ssid.substring(0, 18);
            uint16_t color = ap_list[i].rssi > -50 ? GREEN : (ap_list[i].rssi > -70 ? YELLOW : RED);
            M5Cardputer.Display.setTextColor(color);
            M5Cardputer.Display.drawString(ssid + " (" + String(ap_list[i].client_count) + ")", 5, y);
            M5Cardputer.Display.setTextColor(WHITE);
            y += 14;
        }
    } else {
        M5Cardputer.Display.drawString("No networks scanned", 20, 60);
        M5Cardputer.Display.drawString("Go to Scan Mode (S)", 20, 80);
    }

    M5Cardputer.Display.drawFastHLine(0, 160, 240, 0x7BEF);
    M5Cardputer.Display.drawString("G:radar V:size D:dbg T:test S:scan", 5, 170);
}

void drawDebugScreen() {
    if (last_drawn_mode != MODE_DEBUG) {
        M5Cardputer.Display.fillScreen(BLACK);
        last_drawn_mode = MODE_DEBUG;
    }

    M5Cardputer.Display.fillRect(0, 0, 240, 180, BLACK);
    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("DEBUG MODE", 5, 3);
    M5Cardputer.Display.drawFastHLine(0, 18, 240, WHITE);

    String tabs[] = {"[PACKETS]", "[CHANNEL]", "[CALIBRATE]"};
    for (int i = 0; i < 3; i++) {
        int x = 3 + i*80;
        if (i == debug_tab) { M5Cardputer.Display.fillRect(x, 20, 78, 16, WHITE); M5Cardputer.Display.setTextColor(BLACK); }
        else                { M5Cardputer.Display.drawRect(x, 20, 78, 16, WHITE); M5Cardputer.Display.setTextColor(WHITE); }
        M5Cardputer.Display.drawString(tabs[i], x+3, 21);
        M5Cardputer.Display.setTextColor(WHITE);
    }

    int y = 40;
    switch (debug_tab) {
        case DEBUG_PACKETS: {
            char buf[48];
            snprintf(buf, sizeof(buf), "Total: %lu", packet_count_total);
            M5Cardputer.Display.drawString(buf, 5, y); y+=16;
            snprintf(buf, sizeof(buf), "Per sec: %lu", packet_count_snapshot);
            M5Cardputer.Display.drawString(buf, 5, y); y+=16;
            snprintf(buf, sizeof(buf), "RSSI(EMA): %.1f dBm", current_amplitude);
            M5Cardputer.Display.drawString(buf, 5, y); y+=16;
            snprintf(buf, sizeof(buf), "Last pkt: %lu ms", millis() - last_packet_time);
            M5Cardputer.Display.drawString(buf, 5, y); y+=16;
            if (is_calibrated) {
                snprintf(buf, sizeof(buf), "Base: %.1f dBm", csi_baseline);
                M5Cardputer.Display.drawString(buf, 5, y); y+=16;
                snprintf(buf, sizeof(buf), "Dev: %.2f", current_deviation);
                M5Cardputer.Display.drawString(buf, 5, y); y+=16;
            }
            if (!ap_list.empty() && selected_ap < (int)ap_list.size()) {
                auto it = ap_clients.find(ap_list[selected_ap].bssid_str);
                if (it != ap_clients.end()) {
                    char buf2[32];
                    snprintf(buf2, sizeof(buf2), "Clients: %d", (int)it->second.size());
                    M5Cardputer.Display.drawString(buf2, 5, y); y+=16;
                }
            }
            M5Cardputer.Display.drawString("F:reset R:cal", 5, y+10);
            break;
        }
        case DEBUG_CHANNEL:
            M5Cardputer.Display.drawString("Ch: " + String(current_channel), 5, y); y+=20;
            for (int i=1; i<=13; i++) {
                int x = 10 + (i-1)*17;
                M5Cardputer.Display.fillRect(x, y, 14, 14, i==current_channel ? GREEN : 0x39E7);
                if (i==1||i==6||i==11) {
                    M5Cardputer.Display.setTextColor(BLACK);
                    M5Cardputer.Display.drawString(String(i), x+3, y+1);
                    M5Cardputer.Display.setTextColor(WHITE);
                }
            }
            M5Cardputer.Display.drawString("</>:change 1/6/11:jump", 5, y+20);
            break;
        case DEBUG_CALIBRATE:
            M5Cardputer.Display.drawString("Cal: " + String(is_calibrated ? "YES" : "NO"), 5, y); y+=16;
            M5Cardputer.Display.drawString("Thr: " + String(movement_threshold,1), 5, y); y+=16;
            M5Cardputer.Display.drawString("EMA a: " + String(EMA_ALPHA, 2), 5, y); y+=16;
            M5Cardputer.Display.drawString("R:cal H/L:thr", 5, y+10);
            break;
    }
    M5Cardputer.Display.drawString("P/C/A:tabs M/D/T/B:mode", 5, 170);
}

void drawTestScreen(float deviation, bool movement) {
    if (last_drawn_mode != MODE_TEST) {
        M5Cardputer.Display.fillScreen(BLACK);
        last_drawn_mode = MODE_TEST;
    }

    if (radar_view_active && is_calibrated) { drawRadarView(); return; }

    M5Cardputer.Display.fillRect(0, 0, 240, 180, BLACK);
    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("TEST MODE", 5, 2);
    M5Cardputer.Display.drawString("SimHome (Ch6)", 120, 2);
    M5Cardputer.Display.drawFastHLine(0, 15, 240, WHITE);

    char buf[32];
    snprintf(buf, sizeof(buf), "Thr:%.1f", movement_threshold);
    M5Cardputer.Display.drawString(buf, 5, 17);
    snprintf(buf, sizeof(buf), "Dev:%.1f", deviation);
    M5Cardputer.Display.drawString(buf, 100, 17);
    snprintf(buf, sizeof(buf), "Hits:%d", movement_counter);
    M5Cardputer.Display.drawString(buf, 175, 17);
    M5Cardputer.Display.drawString("G:radar V:size SPACE:move", 5, 32);

    int graph_top = 48, graph_bottom = 145, graph_left = 10, graph_right = 230;
    int graph_width = graph_right - graph_left, graph_height = graph_bottom - graph_top;

    M5Cardputer.Display.drawRect(graph_left, graph_top, graph_width, graph_height, 0x39E7);
    int center_x = graph_left + graph_width / 2;
    M5Cardputer.Display.drawFastVLine(center_x, graph_top, graph_height, WHITE);
    M5Cardputer.Display.drawString("C", center_x - 3, graph_top + 1);

    int threshold_offset = map(constrain(movement_threshold * 5, 0, 100), 0, 100, 0, graph_width / 2 - 5);
    for (int y = graph_top; y < graph_bottom; y += 4) {
        M5Cardputer.Display.drawPixel(center_x - threshold_offset, y, YELLOW);
        M5Cardputer.Display.drawPixel(center_x + threshold_offset, y, YELLOW);
    }

    if (graph_points.size() > 1) {
        float max_dev = max(movement_threshold * 3, deviation_peak + 2);
        for (int i = 1; i < (int)graph_points.size(); i++) {
            int y1_pos = map(i - 1, 0, max_graph_points - 1, graph_bottom - 2, graph_top + 2);
            int y2_pos = map(i, 0, max_graph_points - 1, graph_bottom - 2, graph_top + 2);
            float dev2 = graph_points[i].deviation;
            int offset2 = map(constrain(dev2 * 5, 0, max_dev * 5), 0, max_dev * 5, 0, graph_width / 2 - 5);
            uint16_t color = dev2 > movement_threshold ? RED : (dev2 > movement_threshold * 0.7 ? YELLOW : GREEN);
            M5Cardputer.Display.fillCircle(center_x + offset2, y2_pos, 2, color);
            if (abs(y2_pos - y1_pos) < 10) {
                float dev1 = graph_points[i - 1].deviation;
                int offset1 = map(constrain(dev1 * 5, 0, max_dev * 5), 0, max_dev * 5, 0, graph_width / 2 - 5);
                M5Cardputer.Display.drawLine(center_x + offset1, y1_pos, center_x + offset2, y2_pos, color);
            }
        }
    }

    M5Cardputer.Display.drawFastHLine(0, 152, 240, 0x7BEF);
    if (movement) {
        M5Cardputer.Display.fillRect(0, 154, 240, 14, RED);
        M5Cardputer.Display.setTextColor(WHITE);
        M5Cardputer.Display.drawString("MOVEMENT DETECTED", 40, 155);
        M5Cardputer.Display.setTextColor(WHITE);
    } else {
        M5Cardputer.Display.drawString("No movement", 60, 155);
    }
    M5Cardputer.Display.drawString("SPC:move R:cal F:rst H/L:thr B:back", 5, 172);
}

void handleScanKeys() {
    if (!isSinglePress()) return;
    if (M5Cardputer.Keyboard.isKeyPressed('g') || M5Cardputer.Keyboard.isKeyPressed('G')) {
        if (is_calibrated) { radar_view_active = !radar_view_active; if (radar_view_active) { radar_points.clear(); last_radar_update = millis(); } M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('v') || M5Cardputer.Keyboard.isKeyPressed('V')) {
        if (radar_view_active && is_calibrated) { if (radar_size == RADAR_SMALL) radar_size = RADAR_MEDIUM; else if (radar_size == RADAR_MEDIUM) radar_size = RADAR_LARGE; else radar_size = RADAR_SMALL; M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('t') || M5Cardputer.Keyboard.isKeyPressed('T')) { test_movement_active = false; test_simulated_deviation = 0; radar_view_active = false; switchMode(MODE_TEST); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('m') || M5Cardputer.Keyboard.isKeyPressed('M')) { switchMode(MODE_MONITOR); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('d') || M5Cardputer.Keyboard.isKeyPressed('D')) { switchMode(MODE_DEBUG); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('s') || M5Cardputer.Keyboard.isKeyPressed('S')) { scanWiFi(); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('b') || M5Cardputer.Keyboard.isKeyPressed('B')) { scan_state = SCAN_IDLE; radar_view_active = false; return; }
    if (scan_state == SCAN_LIST) {
        if (M5Cardputer.Keyboard.isKeyPressed(';') && selected_ap > 0) { selected_ap--; if (selected_ap < list_offset) list_offset--; }
        if (M5Cardputer.Keyboard.isKeyPressed('.') && selected_ap < (int)ap_list.size()-1) { selected_ap++; if (selected_ap >= list_offset+items_per_page) list_offset++; }
        if (M5Cardputer.Keyboard.isKeyPressed(13) || M5Cardputer.Keyboard.isKeyPressed('/')) { if (!ap_list.empty()) calibrate(); }
    }
}

void handleMonitorKeys() {
    if (!isSinglePress()) return;
    if (M5Cardputer.Keyboard.isKeyPressed('g') || M5Cardputer.Keyboard.isKeyPressed('G')) {
        if (is_calibrated) { radar_view_active = !radar_view_active; if (radar_view_active) { radar_points.clear(); last_radar_update = millis(); } M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('v') || M5Cardputer.Keyboard.isKeyPressed('V')) {
        if (radar_view_active && is_calibrated) { if (radar_size == RADAR_SMALL) radar_size = RADAR_MEDIUM; else if (radar_size == RADAR_MEDIUM) radar_size = RADAR_LARGE; else radar_size = RADAR_SMALL; M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('t') || M5Cardputer.Keyboard.isKeyPressed('T')) { test_movement_active = false; test_simulated_deviation = 0; radar_view_active = false; switchMode(MODE_TEST); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('d') || M5Cardputer.Keyboard.isKeyPressed('D')) { switchMode(MODE_DEBUG); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('s') || M5Cardputer.Keyboard.isKeyPressed('S')) { switchMode(MODE_SCAN); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('b') || M5Cardputer.Keyboard.isKeyPressed('B')) { switchMode(MODE_SCAN); return; }
}

void handleDebugKeys() {
    if (!isSinglePress()) return;
    if (M5Cardputer.Keyboard.isKeyPressed('g') || M5Cardputer.Keyboard.isKeyPressed('G')) {
        if (is_calibrated) { radar_view_active = !radar_view_active; if (radar_view_active) { radar_points.clear(); last_radar_update = millis(); } M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('v') || M5Cardputer.Keyboard.isKeyPressed('V')) {
        if (radar_view_active && is_calibrated) { if (radar_size == RADAR_SMALL) radar_size = RADAR_MEDIUM; else if (radar_size == RADAR_MEDIUM) radar_size = RADAR_LARGE; else radar_size = RADAR_SMALL; M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('t') || M5Cardputer.Keyboard.isKeyPressed('T')) { test_movement_active = false; test_simulated_deviation = 0; radar_view_active = false; switchMode(MODE_TEST); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('m') || M5Cardputer.Keyboard.isKeyPressed('M')) { if (is_calibrated) switchMode(MODE_MONITOR); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('s') || M5Cardputer.Keyboard.isKeyPressed('S')) { switchMode(MODE_SCAN); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('b') || M5Cardputer.Keyboard.isKeyPressed('B')) { switchMode(MODE_SCAN); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('p')) { debug_tab = DEBUG_PACKETS; last_drawn_mode = (AppMode)-1; }
    if (M5Cardputer.Keyboard.isKeyPressed('c')) { debug_tab = DEBUG_CHANNEL; last_drawn_mode = (AppMode)-1; }
    if (M5Cardputer.Keyboard.isKeyPressed('a')) { debug_tab = DEBUG_CALIBRATE; last_drawn_mode = (AppMode)-1; }
    if (debug_tab == DEBUG_PACKETS) {
        if (M5Cardputer.Keyboard.isKeyPressed('f') || M5Cardputer.Keyboard.isKeyPressed('F')) { packet_count_total = 0; deviation_peak = 0; radar_points.clear(); graph_points.clear(); }
        if (M5Cardputer.Keyboard.isKeyPressed('r') || M5Cardputer.Keyboard.isKeyPressed('R')) calibrate();
    }
    if (debug_tab == DEBUG_CHANNEL) {
        if (M5Cardputer.Keyboard.isKeyPressed(',')) { if (current_channel > 1) { current_channel--; initPassiveCSI(current_channel); } }
        if (M5Cardputer.Keyboard.isKeyPressed('/')) { if (current_channel < 13) { current_channel++; initPassiveCSI(current_channel); } }
        if (M5Cardputer.Keyboard.isKeyPressed('1')) { current_channel = 1; initPassiveCSI(current_channel); }
        if (M5Cardputer.Keyboard.isKeyPressed('6')) { current_channel = 6; initPassiveCSI(current_channel); }
        if (M5Cardputer.Keyboard.isKeyPressed('!')) { current_channel = 11; initPassiveCSI(current_channel); }
    }
    if (debug_tab == DEBUG_CALIBRATE) {
        if (M5Cardputer.Keyboard.isKeyPressed('r') || M5Cardputer.Keyboard.isKeyPressed('R')) calibrate();
        if (M5Cardputer.Keyboard.isKeyPressed('h') || M5Cardputer.Keyboard.isKeyPressed('H')) { movement_threshold += 0.5; if (movement_threshold > 30) movement_threshold = 1; }
        if (M5Cardputer.Keyboard.isKeyPressed('l') || M5Cardputer.Keyboard.isKeyPressed('L')) { movement_threshold -= 0.5; if (movement_threshold < 1) movement_threshold = 30; }
    }
}

void handleTestKeys() {
    if (!isSinglePress()) return;
    if (M5Cardputer.Keyboard.isKeyPressed('g') || M5Cardputer.Keyboard.isKeyPressed('G')) {
        if (is_calibrated) { radar_view_active = !radar_view_active; if (radar_view_active) { radar_points.clear(); last_radar_update = millis(); } M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('v') || M5Cardputer.Keyboard.isKeyPressed('V')) {
        if (radar_view_active && is_calibrated) { if (radar_size == RADAR_SMALL) radar_size = RADAR_MEDIUM; else if (radar_size == RADAR_MEDIUM) radar_size = RADAR_LARGE; else radar_size = RADAR_SMALL; M5Cardputer.Display.fillScreen(BLACK); last_drawn_mode = (AppMode)-1; } return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('m') || M5Cardputer.Keyboard.isKeyPressed('M')) { if (is_calibrated) switchMode(MODE_MONITOR); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('d') || M5Cardputer.Keyboard.isKeyPressed('D')) { switchMode(MODE_DEBUG); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('s') || M5Cardputer.Keyboard.isKeyPressed('S')) { switchMode(MODE_SCAN); return; }
    if (M5Cardputer.Keyboard.isKeyPressed('b') || M5Cardputer.Keyboard.isKeyPressed('B')) { switchMode(MODE_SCAN); return; }
    if (M5Cardputer.Keyboard.isKeyPressed(' ')) test_movement_active = !test_movement_active;
    if (M5Cardputer.Keyboard.isKeyPressed('r') || M5Cardputer.Keyboard.isKeyPressed('R')) calibrate();
    if (M5Cardputer.Keyboard.isKeyPressed('f') || M5Cardputer.Keyboard.isKeyPressed('F')) { movement_counter = 0; deviation_peak = 0; radar_points.clear(); graph_points.clear(); }
    if (M5Cardputer.Keyboard.isKeyPressed('h') || M5Cardputer.Keyboard.isKeyPressed('H')) { movement_threshold += 0.5; if (movement_threshold > 30) movement_threshold = 1; }
    if (M5Cardputer.Keyboard.isKeyPressed('l') || M5Cardputer.Keyboard.isKeyPressed('L')) { movement_threshold -= 0.5; if (movement_threshold < 1) movement_threshold = 30; }
}

void setup() {
    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);
    M5Cardputer.Display.setRotation(1);
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setTextColor(WHITE);
    M5Cardputer.Display.drawString("WiFi RSSI Motion Detector", 30, 35);
    M5Cardputer.Display.drawString("by imnoturbadboy", 15, 75);
    M5Cardputer.Display.drawString("https://github.com/imnoturbadboy", 15, 95);
    delay(2000);
    current_mode = MODE_SCAN;
    WiFi.mode(WIFI_MODE_NULL);
    delay(100);
}

void loop() {
    M5Cardputer.update();

    if (current_mode != MODE_TEST && millis() - last_packet_report > 1000) {
        packet_count_snapshot = packet_count_total;
        packet_count_total = 0;
        last_packet_report = millis();
    }

    if (millis() - peak_reset_time > 5000) {
        deviation_peak = 0;
        peak_reset_time = millis();
    }

    switch (current_mode) {
        case MODE_SCAN:    handleScanKeys();  drawScanScreen();  break;
        case MODE_MONITOR: handleMonitorKeys(); drawMonitorScreen(); break;
        case MODE_DEBUG:   handleDebugKeys();  drawDebugScreen(); break;
        case MODE_TEST: {
            handleTestKeys();
            updateTestSimulation();
            if (!radar_view_active && millis() - last_graph_add > 200) {
                GraphPoint gp;
                gp.deviation = test_simulated_deviation;
                gp.timestamp = millis();
                graph_points.push_back(gp);
                while (graph_points.size() > max_graph_points)
                    graph_points.erase(graph_points.begin());
                last_graph_add = millis();
            }
            float dev = test_simulated_deviation;
            bool mov = (dev > movement_threshold);
            static bool was_mov = false;
            if (mov && !was_mov) movement_counter++;
            was_mov = mov;
            drawTestScreen(dev, mov);
            break;
        }
    }
    delay(10);
}
