#pragma once
#include <Adafruit_PN532.h>

class NfcExtended : public Adafruit_PN532 {
public:
    NfcExtended(uint8_t sda, uint8_t scl) : Adafruit_PN532(sda, scl) {}

    bool readSig(uint8_t* sigOut) {
        uint8_t cmd[3]   = { PN532_COMMAND_INCOMMUNICATETHRU, 0x3C, 0x00 };
        uint8_t resp[40] = { 0 };

        if (!sendCommandCheckAck(cmd, sizeof(cmd))) {
            //Serial.println("SIG_DEBUG|sendCmd_FAILED");
            return false;
        }

        delay(10);
        readdata(resp, sizeof(resp)); // OK — dipanggil dari dalam subclass

        //Serial.print("SIG_DEBUG|frame=");
        for (int i = 0; i < 40; i++) {
            char buf[3];
            sprintf(buf, "%02X", resp[i]);
            //Serial.print(buf);
        }
        //Serial.println();

        if (resp[0] != 0x00 || resp[1] != 0x00 || resp[2] != 0xFF) {
            //Serial.println("SIG_DEBUG|BAD_HEADER");
            return false;
        }
        if (resp[5] != 0xD5 || resp[6] != 0x43) {
            //Serial.println("SIG_DEBUG|BAD_TFI");
            return false;
        }
        if (resp[7] != 0x00) {
            //Serial.print("SIG_DEBUG|STATUS_ERR=");
            //Serial.println(resp[7], HEX);
            return false;
        }

        memcpy(sigOut, resp + 8, 32);

        //Serial.print("SIG_RAW|");
        for (int i = 0; i < 32; i++) {
            char buf[3];
            sprintf(buf, "%02X", sigOut[i]);
            //Serial.print(buf);
        }
        //Serial.println();

        return true;
    }
};