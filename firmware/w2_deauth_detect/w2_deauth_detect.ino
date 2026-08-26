#include <WiFi.h>
#include <esp_wifi.h>
#include <Arduino.h>

#define SERIAL_BAUD       115200
#define HOP_INTERVAL_MS   100
#define REPORT_INTERVAL   5000
#define DEAUTH_THRESHOLD_WARN    5
#define DEAUTH_THRESHOLD_CRIT    20
#define MAX_TRACKED_MACS  20

typedef struct {
  uint8_t mac[6];
  uint8_t reason;
  unsigned long timestamp;
} DeauthEvent;

static DeauthEvent events[64];
static int eventHead = 0;
static int eventCount = 0;

static uint8_t trackedMacs[MAX_TRACKED_MACS][6];
static int deauthCounts[MAX_TRACKED_MACS];
static int trackedCount = 0;

static int currentChannel = 1;
static unsigned long lastHop = 0;
static unsigned long lastReport = 0;
static unsigned long totalDeauths = 0;
static unsigned long totalDisassoc = 0;

const char* reasonCodeStr(uint16_t reason) {
  switch (reason) {
    case 1:  return "Unspecified";
    case 2:  return "Auth no longer valid";
    case 3:  return "Deauth: STA leaving";
    case 4:  return "Inactivity";
    case 5:  return "AP busy";
    case 6:  return "Class 2 frame from non-auth STA";
    case 7:  return "Class 3 frame from non-assoc STA";
    case 8:  return "STA leaving/disassoc";
    case 9:  return "STA not authenticated";
    case 14: return "MIC failure";
    case 15: return "4-way handshake timeout";
    case 16: return "Group key handshake timeout";
    case 17: return "IE in 4-way handshake different";
    default: return "Unknown";
  }
}

const char* threatLevel() {
  if (totalDeauths >= DEAUTH_THRESHOLD_CRIT) return "CRITICAL";
  if (totalDeauths >= DEAUTH_THRESHOLD_WARN)  return "WARNING";
  return "NORMAL";
}

void alertBeep() {
  Serial.print("\a");
}

void trackMac(const uint8_t* mac) {
  for (int i = 0; i < trackedCount; i++) {
    if (memcmp(trackedMacs[i], mac, 6) == 0) {
      deauthCounts[i]++;
      return;
    }
  }
  if (trackedCount < MAX_TRACKED_MACS) {
    memcpy(trackedMacs[trackedCount], mac, 6);
    deauthCounts[trackedCount] = 1;
    trackedCount++;
  }
}

void printMac(const uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    if (mac[i] < 0x10) Serial.print("0");
    Serial.print(mac[i], HEX);
    if (i < 5) Serial.print(":");
  }
}

void wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  if (len < 26) return;

  uint8_t frameType = payload[0] & 0x0C;
  uint8_t frameSubtype = payload[0] & 0xF0;

  bool isDeauth = (frameType == 0x00 && frameSubtype == 0xC0);
  bool isDisassoc = (frameType == 0x00 && frameSubtype == 0xA0);

  if (!isDeauth && !isDisassoc) return;

  const uint8_t* destMac = payload + 4;
  const uint8_t* srcMac = payload + 10;
  uint16_t reason = payload[24] | (payload[25] << 8);

  if (isDeauth) totalDeauths++;
  else totalDisassoc++;

  trackMac(srcMac);

  eventCount++;
  if (eventCount > 64) eventCount = 64;

  events[eventHead].reason = (uint8_t)reason;
  events[eventHead].timestamp = millis();
  memcpy(events[eventHead].mac, srcMac, 6);
  eventHead = (eventHead + 1) % 64;

  Serial.printf("\r\n[%s] %s src=", isDeauth ? "DEAUTH " : "DISASSOC", threatLevel());
  printMac(srcMac);
  Serial.printf(" -> ");
  printMac(destMac);
  Serial.printf(" reason=%d (%s)\r\n", reason, reasonCodeStr(reason));

  if (totalDeauths >= DEAUTH_THRESHOLD_WARN) {
    alertBeep();
  }
}

void printReport() {
  Serial.println("\r\n+==============================================+");
  Serial.println("|      W2 Deauth Detector - Status Report      |");
  Serial.println("+==============================================+");
  Serial.printf("| Threat Level: %-30s|\r\n", threatLevel());
  Serial.printf("| Total Deauth:    %-27ld|\r\n", (long)totalDeauths);
  Serial.printf("| Total Disassoc:  %-27ld|\r\n", (long)totalDisassoc);
  Serial.printf("| Channel:         %-27d|\r\n", currentChannel);
  Serial.println("+----------------------------------------------+");
  Serial.println("| Top Offending MACs:                          |");
  Serial.println("+----------------------------------------------+");

  for (int i = 0; i < trackedCount; i++) {
    Serial.print("| ");
    printMac(trackedMacs[i]);
    Serial.printf("  x%-4d\r\n", deauthCounts[i]);
  }

  if (trackedCount == 0) {
    Serial.println("| (none detected)                             |");
  }

  Serial.println("+----------------------------------------------+");

  if (totalDeauths >= DEAUTH_THRESHOLD_CRIT) {
    Serial.println("!!! CRITICAL: Active deauth attack detected !!!");
  } else if (totalDeauths >= DEAUTH_THRESHOLD_WARN) {
    Serial.println("!! WARNING: Possible deauth activity !!");
  } else {
    Serial.println("  Status: Normal operation");
  }
}

void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(500);

  Serial.println("+----------------------------------------------+");
  Serial.println("|    W2 WiFi Deauth Detector                   |");
  Serial.println("|    Board: ESP32-C6                           |");
  Serial.println("+----------------------------------------------+");

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(wifiSnifferCallback);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

  Serial.printf("Promiscuous mode active on channel %d\r\n", currentChannel);
  Serial.printf("Thresholds: warn=%d, critical=%d deauth/s\r\n",
                DEAUTH_THRESHOLD_WARN, DEAUTH_THRESHOLD_CRIT);

  lastReport = millis();
  lastHop = millis();
}

void loop() {
  unsigned long now = millis();

  if (now - lastHop >= HOP_INTERVAL_MS) {
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastHop = now;
  }

  if (now - lastReport >= REPORT_INTERVAL) {
    printReport();
    totalDeauths = 0;
    totalDisassoc = 0;
    trackedCount = 0;
    eventCount = 0;
    lastReport = now;
  }

  delay(10);
}
