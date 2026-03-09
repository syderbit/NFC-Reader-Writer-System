# 📡 NFC Reader/Writer System

Sistem baca/tulis kartu NFC berbasis **Web Serial API** (Vue/TypeScript) dan **Arduino/ESP32** dengan modul PN532. Mendukung kartu **NTAG213/215/216** dan **MIFARE Classic 1K/4K**, dilengkapi verifikasi keaslian kartu menggunakan **NXP Originality Signature (ECDSA secp128r1)** dan **enkripsi AES-128** berbasis UID untuk mencegah clone data antar kartu.

---

## 🏗️ Arsitektur Sistem

```
┌─────────────────────────────────────────────────────┐
│                  Browser (Vue/TypeScript)            │
│                                                     │
│   ┌─────────────┐        ┌──────────────────────┐  │
│   │  UI / State │◄──────►│  libNFC.ts           │  │
│   │  isConnected│        │  connectSerial()      │  │
│   │  isWriting  │        │  disconnectSerial()   │  │
│   └─────────────┘        │  readLoop()           │  │
│                          │  handleResponse()     │  │
│                          │  writeTag(payload)    │  │
│                          └──────────┬───────────┘  │
└─────────────────────────────────────┼───────────────┘
                                      │ Web Serial API
                                      │ USB / baudRate 115200
┌─────────────────────────────────────┼───────────────┐
│                ESP32 / Arduino      │               │
│                                     ▼               │
│   ┌──────────────────────────────────────────────┐  │
│   │  sketch_mar7c.ino                            │  │
│   │  loop()                                      │  │
│   │   ├─ Serial.available()?                     │  │
│   │   │    ├─ "WRITE|..." → handleWrite()        │  │
│   │   │    └─ unknown    → UNKNOWN_CMD|...       │  │
│   │   └─ handleRead()  ← default, terus-menerus  │  │
│   └──────────────────────────────────────────────┘  │
│                        │                            │
│          ┌─────────────▼──────────────┐             │
│          │  SigVerification.h         │             │
│          │  verifyOriginality()       │             │
│          │   ├─ NTAG   → reactivate   │             │
│          │   │           → readSig()  │             │
│          │   │           → ecdsa_verify()           │
│          │   └─ MIFARE → VERIFY_SKIP  │             │
│          └─────────────┬──────────────┘             │
│                        │                            │
│          ┌─────────────▼──────────────┐             │
│          │  NfcExtended.h             │             │
│          │  extends Adafruit_PN532    │             │
│          │  readSig()                 │             │
│          │   └─ InCommunicateThru     │             │
│          │      (0x42) + READ_SIG     │             │
│          │      (0x3C 0x00)           │             │
│          └─────────────┬──────────────┘             │
└────────────────────────┼────────────────────────────┘
                         │ I2C — SDA=8, SCL=9
              ┌──────────▼──────────┐
              │     PN532 Module    │
              └──────────┬──────────┘
                         │ ISO14443A 13.56 MHz
              ┌──────────┴──────────┐
              │                     │
         ┌────▼────┐          ┌─────▼────┐
         │  NTAG   │          │  MIFARE  │
         │213/215/ │          │Classic   │
         │216      │          │1K / 4K   │
         └─────────┘          └──────────┘
```

---

## 📁 Struktur File

```
project/
├── sketch_mar7c.ino     # setup(), loop(), handleRead(), handleWrite()
│                        # scanTag(), ntag_*, mifare_*
├── SigVerification.h    # verifyOriginality(), reactivateCard()
│                        # ntag_readSignature(), NXP public key
│                        # encryptPayload(), decryptPayload()
│                        # uidToKey(), pkcs7Pad(), pkcs7Unpad()
│                        # globals: nfc, uid, uidLength, CardType
├── NfcExtended.h        # class NfcExtended extends Adafruit_PN532
│                        # readSig() via InCommunicateThru
├── ecc.h / ecc.c        # easy-ecc library (secp128r1)
└── vue/
    └── libNFC.ts        # connectSerial(), readLoop(),
                         # handleResponse(), writeTag()
```

---

## 🔄 Alur Komunikasi

### 📖 Default: Baca Kartu Terus-menerus

```
loop()
  └─► handleRead()                         [sketch_mar7c.ino]
        ├─► scanTag()
        │     ├─ UID 7 byte → CARD_NTAG
        │     └─ UID 4 byte → CARD_MIFARE_1K
        │
        ├─► verifyOriginality()            [SigVerification.h]
        │     ├─ MIFARE → VERIFY_SKIP|MIFARE_NO_SIG → return true
        │     └─ NTAG:
        │          ├─► reactivateCard()    — InRelease + readPassiveTargetID
        │          ├─► ntag_readSignature()
        │          │    └─► nfc.readSig()  [NfcExtended.h]
        │          │          └─ InCommunicateThru 0x3C 0x00
        │          │             parse frame → sigRaw[32]
        │          ├─ cek Fudan clone (signature = UID diulang)
        │          └─► ecdsa_verify(NXP_PUBKEY_NTAG, UID, sig)
        │
        ├─► baca data kartu
        │     ├─ NTAG   → ntag_readTag()   (NDEF Text Record)
        │     └─ MIFARE → mifare_readTag() (length header + raw)
        │
        ├─► decryptPayload(raw, UID)        [SigVerification.h]
        │     ├─ OK    → data plaintext
        │     └─ GAGAL → READ_CLONE_DETECTED|UID|CARD_TYPE
        │
        └─► Serial.println("READ|UID|CARD_TYPE|DATA")
              atau "READ_UNVERIFIED|UID|CARD_TYPE|DATA"

Browser readLoop()
  └─► buffer per '\n' → handleResponse()
        └─ case "READ" / "READ_UNVERIFIED" → update UI
```

### ✍️ Write Kartu

```
Browser
  └─► writeTag(payload)
        └─► sendCommand("WRITE|payload") → Serial TX

loop()
  └─► Serial.available() → handleWrite()   [sketch_mar7c.ino]
        ├─► Validasi payload
        │     ├─ kosong               → WRITE_FAIL|EMPTY_PAYLOAD
        │     ├─ > 128 char           → WRITE_FAIL|PAYLOAD_TOO_LONG
        │     └─ non-ASCII (< 32/>126)→ WRITE_FAIL|INVALID_CHARS
        │
        ├─► Tunggu kartu (timeout 5 detik)
        │     └─► Serial.println("WRITE_WAITING|PLACE_CARD")
        │         timeout → WRITE_FAIL|TIMEOUT_NO_CARD
        │
        ├─► Enkripsi payload
        │     └─► encryptPayload(payload, UID) → hex string
        │
        ├─► Tulis data terenkripsi
        │     ├─ NTAG   → ntag_writeTag()   (NDEF, retry 3x + verify per page)
        │     └─ MIFARE → mifare_writeTag() (length header + raw, retry 3x)
        │     └─ gagal  → WRITE_FAIL|HARDWARE_ERROR|UID|CARD_TYPE
        │
        └─► Verifikasi: baca ulang & bandingkan dengan payload
              ├─ cocok → WRITE_SUCCESS|UID|CARD_TYPE
              └─ beda  → WRITE_FAIL|VERIFY_MISMATCH|UID|CARD_TYPE
```

---

## 📨 Protokol Serial

Semua pesan diakhiri `\n`, field dipisah `|`. Baudrate **115200**.

### ⬇️ Arduino → Browser

| Pesan | Keterangan |
|---|---|
| `NFC_READY` | Modul PN532 siap |
| `PN532_NOT_FOUND` | Modul PN532 tidak terdeteksi |
| `READ\|UID\|CARD_TYPE\|DATA` | Baca kartu berhasil + terverifikasi |
| `READ_UNVERIFIED\|UID\|CARD_TYPE\|DATA` | Baca berhasil tapi verifikasi gagal |
| `READ_CLONE_DETECTED\|UID\|CARD_TYPE` | Data tidak bisa didekripsi — kemungkinan clone |
| `VERIFY_OK\|GENUINE_CARD` | Kartu NXP genuine |
| `VERIFY_SKIP\|MIFARE_NO_SIG` | MIFARE Classic, skip verifikasi |
| `VERIFY_FAIL\|REASON` | Verifikasi gagal (lihat tabel reason) |
| `WRITE_WAITING\|PLACE_CARD` | Menunggu kartu ditempel |
| `WRITE_SUCCESS\|UID\|CARD_TYPE` | Tulis berhasil + data terverifikasi |
| `WRITE_FAIL\|REASON` | Tulis gagal sebelum akses kartu |
| `WRITE_FAIL\|REASON\|UID\|CARD_TYPE` | Tulis gagal setelah kartu terdeteksi |
| `UNKNOWN_CMD\|cmd` | Perintah tidak dikenal |

### ⬆️ Browser → Arduino

| Pesan | Keterangan |
|---|---|
| `WRITE\|payload` | Tulis data ke kartu (ASCII printable, maks 128 char) |

### ⚠️ Reason Codes

| Reason | Konteks | Keterangan |
|---|---|---|
| `EMPTY_PAYLOAD` | WRITE_FAIL | Payload kosong |
| `PAYLOAD_TOO_LONG` | WRITE_FAIL | Melebihi 128 karakter |
| `INVALID_CHARS` | WRITE_FAIL | Karakter non-ASCII printable |
| `TIMEOUT_NO_CARD` | WRITE_FAIL | Tidak ada kartu dalam 5 detik |
| `HARDWARE_ERROR` | WRITE_FAIL | Gagal tulis ke kartu |
| `VERIFY_MISMATCH` | WRITE_FAIL | Data terbaca != payload yang ditulis |
| `CANNOT_READ_SIGNATURE` | VERIFY_FAIL | READ_SIG command gagal |
| `REACTIVATE_FAILED` | VERIFY_FAIL | Kartu tidak bisa di-reactivate |
| `FAKE_FUDAN_SIGNATURE` | VERIFY_FAIL | Kartu clone Fudan terdeteksi |
| `INVALID_SIGNATURE` | VERIFY_FAIL | ECDSA verify gagal |

---

## 🔐 Verifikasi NXP Originality Signature

Kartu NTAG asli buatan NXP menyimpan **ECDSA signature** yang di-sign NXP menggunakan private key mereka saat produksi. Sistem memverifikasi signature menggunakan **NXP public key (secp128r1)** via library `easy-ecc`.

```
NXP (saat produksi kartu)
  └─► sign(UID, NXP_private_key) → signature disimpan permanen di kartu

Arduino saat handleRead() / handleWrite()
  └─► reactivateCard()
        └─► InRelease → readPassiveTargetID ulang
  └─► NfcExtended::readSig()
        └─► InCommunicateThru (0x42) + READ_SIG (0x3C 0x00)
              └─► parse PN532 frame → sigRaw[32]
  └─► cek Fudan clone (pola UID diulang dalam signature)
  └─► ecdsa_verify(NXP_PUBKEY_NTAG, UID[16], sigRaw[32])
        ├─ 1 → VERIFY_OK|GENUINE_CARD
        └─ 0 → VERIFY_FAIL|INVALID_SIGNATURE
```

> **Mengapa perlu `reactivateCard()`?**
> Setelah `readPassiveTargetID()`, kartu sudah dalam state tertentu dan tidak bisa menerima custom command seperti `READ_SIG` secara langsung. `reactivateCard()` melakukan `InRelease` kemudian scan ulang sehingga kartu kembali ke state awal dan siap menerima command apapun.

> **Mengapa MIFARE di-skip?**
> MIFARE Classic biasa (bukan EV1) tidak memiliki fitur `READ_SIG`. Hanya NTAG213/215/216 yang support originality signature pada implementasi ini.

---

## 🔧 NfcExtended Class

`NfcExtended` merupakan subclass dari `Adafruit_PN532` yang menambahkan fungsi `readSig()`. Fungsi `readdata()` di `Adafruit_PN532` bersifat `protected`, sehingga hanya bisa diakses dari dalam subclass — itulah alasan `readSig()` harus berada di dalam class ini dan tidak bisa dipindah ke file lain.

```
Adafruit_PN532
  ├─ sendCommandCheckAck()  — protected
  ├─ readdata()             — protected
  └─ ...

NfcExtended extends Adafruit_PN532
  └─ readSig()
       ├─ sendCommandCheckAck([0x42, 0x3C, 0x00])
       ├─ readdata(resp[40])
       ├─ validasi frame: 00 00 FF ... D5 43 00
       └─ return sigOut[32] dari resp[8..39]
```

---

## 🛡️ Enkripsi AES-128 Anti-Clone

Data yang ditulis ke kartu dienkripsi menggunakan **AES-128-ECB** dengan **UID kartu sebagai key**. Karena setiap kartu memiliki UID unik, data yang di-copy ke kartu lain tidak bisa didekripsi — kartu clone akan menghasilkan data garbage.

```
Tulis ke kartu A (UID: AABBCCDD1122334):
  payload "Hello"
    → uidToKey(UID) → key[16] = AA BB CC DD 11 22 33 4 00 00 00 00 00 00 00 00
    → AES-128-ECB encrypt + PKCS7 padding
    → hex string "3F9A7B..." → disimpan ke kartu A

Baca kartu A:
  "3F9A7B..." → AES-128-ECB decrypt (key dari UID A) → "Hello" ✅

Clone data ke kartu B (UID: 11223344):
  kartu B berisi "3F9A7B..." (sama persis dengan kartu A)
  → AES-128-ECB decrypt (key dari UID B ← berbeda!)
  → GARBAGE → READ_CLONE_DETECTED ❌
```

**Format data di kartu:**

```
[ AES-128-ECB encrypted hex string ]
  └─ plaintext: payload + PKCS7 padding (kelipatan 16 byte)
  └─ key: UID (7 byte) di-pad ke 16 byte dengan 0x00
```

**Fungsi terkait di `SigVerification.h`:**

| Fungsi | Keterangan |
|---|---|
| `uidToKey(key)` | Konversi UID → AES key 16 byte |
| `pkcs7Pad(buf, len, 16)` | Tambah padding ke kelipatan 16 byte |
| `pkcs7Unpad(buf, len)` | Hapus padding setelah dekripsi |
| `encryptPayload(payload)` | Enkripsi string → hex string |
| `decryptPayload(hexData)` | Dekripsi hex string → plaintext, return `""` jika gagal |

> **Library:** `mbedtls/aes.h` — sudah built-in di ESP32 Arduino core, tidak perlu install tambahan.

> **Catatan:** AES-ECB dipilih karena keterbatasan memori kartu NFC (tidak ada ruang untuk menyimpan IV yang dibutuhkan CBC/CTR). Untuk payload pendek yang terikat ke UID unik, ECB sudah cukup untuk mencegah clone.

---



## 📦 Dependencies

### 🤖 Arduino
| Library | Keterangan |
|---|---|
| `Adafruit_PN532` | Driver modul PN532 via I2C |
| `easy-ecc` | ECDSA verify secp128r1 (copy manual `ecc.h` + `ecc.c`) |
| `mbedtls/aes.h` | AES-128-ECB enkripsi/dekripsi (built-in ESP32) |
| `Wire` | I2C komunikasi ke PN532 (built-in) |

### 🖥️ Vue / TypeScript
| | Keterangan |
|---|---|
| 🌐 Web Serial API | Komunikasi USB serial ke Arduino (Chrome/Edge only) |
| 📥 TextDecoder | Decode `Uint8Array` → string, mode `stream: true` |
| 📤 TextEncoder | Encode string → `Uint8Array` untuk TX |

---

## 💳 Kartu yang Didukung

| Kartu | UID | Originality Signature | Enkripsi Data | Format Data |
|---|---|---|---|---|
| NTAG213 | 7 byte | ✅ ECDSA secp128r1 | ✅ AES-128 + UID | NDEF Text Record |
| NTAG215 | 7 byte | ✅ ECDSA secp128r1 | ✅ AES-128 + UID | NDEF Text Record |
| NTAG216 | 7 byte | ✅ ECDSA secp128r1 | ✅ AES-128 + UID | NDEF Text Record |
| MIFARE Classic 1K | 4 byte | ⚠️ Skip | ✅ AES-128 + UID | Length (2 byte) + raw data |
| MIFARE Classic 4K | 4 byte | ⚠️ Skip | ✅ AES-128 + UID | Length (2 byte) + raw data |
| Fudan clone NTAG | 7 byte | ❌ Ditolak (fake sig) | — | — |