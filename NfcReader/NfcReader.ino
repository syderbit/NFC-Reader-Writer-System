#include <Wire.h>
#include <Adafruit_PN532.h>
#include <SigVerification.h>

// ─────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────

String uidToString() {
  String s = "";
  for (int i = 0; i < uidLength; i++) {
    char buf[3];
    sprintf(buf, "%02X", uid[i]);
    s += buf;
  }
  return s;
}

String getCardStr(CardType card) {
  switch (card) {
    case CARD_NTAG: return "NTAG";
    case CARD_MIFARE_1K: return "MIFARE_1K";
    case CARD_MIFARE_4K: return "MIFARE_4K";
    default: return "UNKNOWN";
  }
}

// ─────────────────────────────────────────────
// Scan Tag
// ─────────────────────────────────────────────

CardType scanTag() {
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    return CARD_UNKNOWN;

  if (uidLength == 4) {
    if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, MIFARE_BLOCK_START, 0, KEY_A_DEFAULT))
      return CARD_MIFARE_1K;
    return CARD_UNKNOWN;
  }

  if (uidLength == 7) return CARD_NTAG;

  return CARD_UNKNOWN;
}

// ═══════════════════════════════════════════════
//  NTAG FUNCTIONS
// ═══════════════════════════════════════════════

bool ntag_verifyPage(int page, uint8_t *expected) {
  uint8_t check[4];
  if (!nfc.ntag2xx_ReadPage(page, check)) return false;
  for (int i = 0; i < 4; i++)
    if (check[i] != expected[i]) return false;
  return true;
}

bool ntag_writePageRetry(int page, uint8_t *data) {
  for (int attempt = 0; attempt < 3; attempt++) {
    if (nfc.ntag2xx_WritePage(page, data)) {
      delay(20);
      if (ntag_verifyPage(page, data)) return true;
    }
    delay(50);
  }
  return false;
}

bool ntag_writeTag(String payload) {
  int payloadLen = payload.length();
  int ndefRecordLen = 1 + 1 + 1 + 1 + 1 + 2 + payloadLen;
  int totalBytes = 1 + 1 + ndefRecordLen + 1;
  int maxBytes = (NTAG213_MAX_PAGE - NTAG213_USER_START + 1) * 4;

  if (totalBytes > maxBytes) return false;

  uint8_t buffer[144];
  memset(buffer, 0, 144);

  int idx = 0;
  buffer[idx++] = 0x03;
  buffer[idx++] = ndefRecordLen;
  buffer[idx++] = 0xD1;
  buffer[idx++] = 0x01;
  buffer[idx++] = (uint8_t)(payloadLen + 3);
  buffer[idx++] = 'T';
  buffer[idx++] = 0x02;
  buffer[idx++] = 'e';
  buffer[idx++] = 'n';
  for (int i = 0; i < payloadLen; i++)
    buffer[idx++] = (uint8_t)payload[i];
  buffer[idx++] = 0xFE;

  int page = NTAG213_USER_START;
  for (int i = 0; i < totalBytes; i += 4) {
    if (page > NTAG213_MAX_PAGE) return false;
    if (!ntag_writePageRetry(page, &buffer[i])) return false;
    page++;
  }
  return true;
}

String ntag_readTag() {
  uint8_t raw[144];
  memset(raw, 0, sizeof(raw));

  int byteIdx = 0;
  for (int page = NTAG213_USER_START; page <= NTAG213_MAX_PAGE; page++) {
    uint8_t buf[4];
    if (!nfc.ntag2xx_ReadPage(page, buf)) break;
    for (int i = 0; i < 4; i++) raw[byteIdx++] = buf[i];
  }

  int i = 0;
  while (i < byteIdx) {
    uint8_t tlvTag = raw[i++];
    if (tlvTag == 0xFE) break;
    if (i >= byteIdx) break;
    uint8_t tlvLen = raw[i++];
    if (tlvTag != 0x03) {
      i += tlvLen;
      continue;
    }

    i++;
    uint8_t typeLen = raw[i++];
    uint8_t payLen = raw[i++];
    i++;

    if (typeLen != 1 || payLen < 3) {
      String fallback = "";
      for (int j = i; j < i + payLen && j < byteIdx; j++) {
        if (raw[j] == 0) break;
        fallback += (char)raw[j];
      }
      return fallback;
    }

    uint8_t statusByte = raw[i++];
    uint8_t langLen = statusByte & 0x3F;
    i += langLen;

    int textLen = payLen - 1 - langLen;
    String result = "";
    for (int j = 0; j < textLen && (i + j) < byteIdx; j++) {
      if (raw[i + j] == 0) break;
      result += (char)raw[i + j];
    }
    return result;
  }
  return "";
}

// ═══════════════════════════════════════════════
//  MIFARE FUNCTIONS
// ═══════════════════════════════════════════════

bool mifare_isSectorTrailer(int block) {
  return ((block + 1) % 4 == 0);
}

bool mifare_authBlock(int block) {
  return nfc.mifareclassic_AuthenticateBlock(uid, uidLength, block, 0, KEY_A_DEFAULT);
}

bool mifare_writeTag(String payload) {
  int payloadLen = payload.length();
  int maxBytes = 16 * 10;

  if (payloadLen > maxBytes - 2) return false;

  uint8_t buffer[maxBytes];
  memset(buffer, 0, maxBytes);
  buffer[0] = (uint8_t)((payloadLen >> 8) & 0xFF);
  buffer[1] = (uint8_t)(payloadLen & 0xFF);
  for (int i = 0; i < payloadLen; i++)
    buffer[2 + i] = (uint8_t)payload[i];

  int block = MIFARE_BLOCK_START;
  int bufIdx = 0;
  int lastSector = -1;

  while (bufIdx < payloadLen + 2) {
    if (block > MIFARE_MAX_BLOCK_1K) return false;
    if (mifare_isSectorTrailer(block)) {
      block++;
      continue;
    }

    int thisSector = block / 4;
    if (thisSector != lastSector) {
      if (!mifare_authBlock(block)) return false;
      lastSector = thisSector;
    }

    uint8_t blockData[16];
    memset(blockData, 0, 16);
    for (int i = 0; i < 16 && (bufIdx + i) < (payloadLen + 2); i++)
      blockData[i] = buffer[bufIdx + i];

    bool success = false;
    for (int attempt = 0; attempt < 3; attempt++) {
      if (nfc.mifareclassic_WriteDataBlock(block, blockData)) {
        success = true;
        break;
      }
      delay(50);
    }
    if (!success) return false;

    bufIdx += 16;
    block++;
  }
  return true;
}

String mifare_readTag() {
  String result = "";
  int block = MIFARE_BLOCK_START;
  int lastSector = -1;
  int totalLen = -1;
  int bytesRead = 0;

  while (block <= MIFARE_MAX_BLOCK_1K) {
    if (mifare_isSectorTrailer(block)) {
      block++;
      continue;
    }

    int thisSector = block / 4;
    if (thisSector != lastSector) {
      if (!mifare_authBlock(block)) break;
      lastSector = thisSector;
    }

    uint8_t blockData[16];
    if (!nfc.mifareclassic_ReadDataBlock(block, blockData)) break;

    for (int i = 0; i < 16; i++) {
      if (totalLen == -1 && bytesRead == 0) {
        totalLen = (int)blockData[i] << 8;
        bytesRead++;
        continue;
      }
      if (totalLen != -1 && result.length() == 0 && bytesRead == 1) {
        totalLen |= (int)blockData[i];
        bytesRead++;
        continue;
      }
      if (bytesRead >= 2 && (int)result.length() < totalLen)
        result += (char)blockData[i];
    }

    if (totalLen >= 0 && (int)result.length() >= totalLen) break;
    block++;
  }
  return result;
}

// ═══════════════════════════════════════════════
//  HANDLE READ & WRITE
// ═══════════════════════════════════════════════

void handleRead() {
  currentCard = scanTag();
  if (currentCard == CARD_UNKNOWN) return;

  String uidStr = uidToString();
  String cardStr = getCardStr(currentCard);
  String isVerified = "READ";

  if (!verifyOriginality(currentCard))
    isVerified = "READ_UNVERIFIED";

  String raw = "";
  if (currentCard == CARD_NTAG)
    raw = ntag_readTag();
  else if (currentCard == CARD_MIFARE_1K || currentCard == CARD_MIFARE_4K)
    raw = mifare_readTag();

  // Dekripsi pakai UID kartu ini
  String data = decryptPayload(raw);
  if (data == "" && raw != "") {
    // Dekripsi gagal → kemungkinan data dari kartu lain (clone)
    Serial.println("READ_CLONE_DETECTED|" + uidStr + "|" + cardStr);
    return;
  }

  Serial.println(isVerified + "|" + uidStr + "|" + cardStr + "|" + data);
}

void handleWrite(const String &cmd) {
  String payload = cmd.substring(6);

  // Validasi payload
  if (payload.length() == 0) {
    Serial.println("WRITE_FAIL|EMPTY_PAYLOAD");
    return;
  }

  if (payload.length() > 128) {
    Serial.println("WRITE_FAIL|PAYLOAD_TOO_LONG");
    return;
  }

  // Hanya izinkan karakter ASCII printable (32–126)
  for (int i = 0; i < payload.length(); i++) {
    char c = payload[i];
    if (c < 32 || c > 126) {
      Serial.println("WRITE_FAIL|INVALID_CHARS");
      return;
    }
  }

  // Tunggu kartu ditempel (timeout 5 detik)
  Serial.println("WRITE_WAITING|PLACE_CARD");

  unsigned long startWait = millis();
  while (true) {
    currentCard = scanTag();
    if (currentCard != CARD_UNKNOWN) break;

    if (millis() - startWait > 5000) {
      Serial.println("WRITE_FAIL|TIMEOUT_NO_CARD");
      return;
    }
    delay(100);
  }

  String uidStr = uidToString();
  String cardStr = getCardStr(currentCard);
  String encrypted = encryptPayload(payload);

  // Eksekusi write
  bool ok = false;
  if (currentCard == CARD_NTAG)
    ok = ntag_writeTag(encrypted);
  else if (currentCard == CARD_MIFARE_1K || currentCard == CARD_MIFARE_4K)
    ok = mifare_writeTag(encrypted);

  if (!ok) {
    Serial.println("WRITE_FAIL|HARDWARE_ERROR|" + uidStr + "|" + cardStr);
    return;
  }

  // Verifikasi: baca ulang & bandingkan
  String verify = "";
  if (currentCard == CARD_NTAG)
    verify = ntag_readTag();
  else if (currentCard == CARD_MIFARE_1K || currentCard == CARD_MIFARE_4K)
    verify = mifare_readTag();

  if (verify == payload)
    Serial.println("WRITE_SUCCESS|" + uidStr + "|" + cardStr);
  else
    Serial.println("WRITE_FAIL|VERIFY_MISMATCH|" + uidStr + "|" + cardStr);
}

// ═══════════════════════════════════════════════
//  SETUP & LOOP
// ═══════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  Wire.begin(SDA_PIN, SCL_PIN);
  nfc.begin();

  if (!nfc.getFirmwareVersion()) {
    Serial.println("PN532_NOT_FOUND");
    while (1)
      ;
  }

  nfc.SAMConfig();
  Serial.println("NFC_READY");
}

void loop() {
  // Cek perintah dari Serial (non-blocking)
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    if (cmd.startsWith("WRITE|")) {
      handleWrite(cmd);
    } else if (cmd != "READ") {
      Serial.println("UNKNOWN_CMD|" + cmd);
    }
  }

  // Default: terus baca kartu
  handleRead();
  delay(1000);  // Debounce scan
}
