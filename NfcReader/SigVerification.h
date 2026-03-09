#define ECC_CURVE secp128r1

#include "ecc.h"
#include <Wire.h>
#include <NfcExtended.h>
#include "mbedtls/aes.h"

#define SDA_PIN 8
#define SCL_PIN 9

#define NTAG213_MAX_PAGE 39
#define NTAG213_USER_START 4
#define MIFARE_BLOCK_START 4
#define MIFARE_BLOCK_SIZE 16
#define MIFARE_MAX_BLOCK_1K 63
#define MIFARE_MAX_BLOCK_4K 255

uint8_t KEY_A_DEFAULT[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

NfcExtended nfc(SDA_PIN, SCL_PIN);

uint8_t uid[7];
uint8_t uidLength;

enum CardType {
  CARD_UNKNOWN,
  CARD_NTAG,
  CARD_MIFARE_1K,
  CARD_MIFARE_4K
};

CardType currentCard = CARD_UNKNOWN;

// NXP Public Key
static const uint8_t NXP_PUBKEY_NTAG[17] = {
  0x03,
  0x49, 0x4E, 0x1A, 0x38, 0x6D, 0x3D, 0x3C, 0xFE,
  0x3D, 0xC1, 0x0E, 0x5D, 0xE6, 0x8A, 0x49, 0x9B
};

// Reactivate kartu
bool reactivateCard() {
  // InRelease target 1
  uint8_t releaseCmd[] = { 0x52, 0x01 };
  uint8_t releaseResp[4];
  uint8_t releaseLen = sizeof(releaseResp);
  nfc.inDataExchange(releaseCmd, sizeof(releaseCmd), releaseResp, &releaseLen);
  delay(20);

  // Scan ulang — simpan UID baru ke uid & uidLength global
  return nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 1000);
}

//  Baca Signature NTAG via InCommunicateThru
bool ntag_readSignature(uint8_t* sigOut) {
  return nfc.readSig(sigOut);  // delegate ke NfcExtended
}

//  Verifikasi Originality
bool verifyOriginality(CardType card) {
  if (card == CARD_MIFARE_1K || card == CARD_MIFARE_4K) {
    Serial.println("VERIFY_SKIP|MIFARE_NO_SIG");
    return true;
  }

  // Reactivate dulu agar kartu siap terima custom command
  if (!reactivateCard()) {
    Serial.println("VERIFY_FAIL|REACTIVATE_FAILED");
    return false;
  }

  uint8_t sigRaw[32] = { 0 };
  if (!ntag_readSignature(sigRaw)) {
    Serial.println("VERIFY_FAIL|CANNOT_READ_SIGNATURE");
    return false;
  }

  // Deteksi Fudan clone: signature = UID diulang
  bool isFake = true;
  for (int i = 0; i < 32 && isFake; i++) {
    if (sigRaw[i] != sigRaw[i % uidLength]) isFake = false;
  }
  if (isFake) {
    Serial.println("VERIFY_FAIL|FAKE_FUDAN_SIGNATURE");
    return false;
  }

  // Message = UID raw pad ke 16 byte
  uint8_t msgHash[16] = { 0 };
  memcpy(msgHash, uid, uidLength);

  int result = ecdsa_verify(NXP_PUBKEY_NTAG, msgHash, sigRaw);

  if (!result) {
    Serial.println("VERIFY_FAIL|INVALID_SIGNATURE");
    return false;
  }

  Serial.println("VERIFY_OK|GENUINE_CARD");
  return true;
}


//
//  Prevent Cloning Kartu
//
// ─── Key dari UID (pad ke 16 byte) ───────────────────────────────────────────
void uidToKey(uint8_t* key) {
    memset(key, 0, 16);
    memcpy(key, uid, uidLength);
}

//  PKCS7 padding 
void pkcs7Pad(uint8_t* buf, int dataLen, int blockSize) {
  uint8_t padVal = blockSize - (dataLen % blockSize);
  for (int i = dataLen; i < dataLen + padVal; i++)
    buf[i] = padVal;
}

int pkcs7Unpad(uint8_t* buf, int len) {
  if (len == 0) return 0;
  uint8_t padVal = buf[len - 1];
  if (padVal > 16 || padVal == 0) return len;
  return len - padVal;
}

//  Enkripsi 
String encryptPayload(const String& payload) {
  uint8_t key[16];
  uidToKey(key);

  int payLen = payload.length();
  int padLen = 16 - (payLen % 16);
  int totalLen = payLen + padLen;

  uint8_t buf[totalLen];
  memset(buf, 0, totalLen);
  for (int i = 0; i < payLen; i++) buf[i] = (uint8_t)payload[i];
  pkcs7Pad(buf, payLen, 16);

  uint8_t out[totalLen];
  memset(out, 0, totalLen);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 128);
  for (int i = 0; i < totalLen; i += 16)
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, buf + i, out + i);
  mbedtls_aes_free(&aes);

  String result = "";
  for (int i = 0; i < totalLen; i++) {
    char h[3];
    sprintf(h, "%02X", out[i]);
    result += h;
  }
  return result;
}

//  Dekripsi 
String decryptPayload(const String& hexData) {
  int hexLen = hexData.length();
  if (hexLen == 0 || hexLen % 2 != 0) return "";

  int dataLen = hexLen / 2;
  if (dataLen % 16 != 0) return "";

  uint8_t buf[dataLen];
  for (int i = 0; i < dataLen; i++) {
    char h[3] = { hexData[i * 2], hexData[i * 2 + 1], 0 };
    buf[i] = (uint8_t)strtol(h, nullptr, 16);
  }

  uint8_t key[16];
  uidToKey(key);

  uint8_t out[dataLen];
  memset(out, 0, dataLen);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, key, 128);
  for (int i = 0; i < dataLen; i += 16)
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, buf + i, out + i);
  mbedtls_aes_free(&aes);

  int realLen = pkcs7Unpad(out, dataLen);

  String result = "";
  for (int i = 0; i < realLen; i++) {
    if (out[i] == 0) break;
    result += (char)out[i];
  }
  return result;
}