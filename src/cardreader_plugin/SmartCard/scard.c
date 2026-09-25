/**
 * MIT-License
 * Copyright (c) 2018 by nolm <nolan@nolm.name>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Modified version.
 */

#include "scard.h"
#include "spad0.h"
#include <windows.h>
#include <winscard.h>
// #include <tchar.h>
// #include <thread>

extern char module[];

#define MAX_APDU_SIZE 255
extern int readCooldown;
extern bool readAccessCode;
// set to detect all cards, reduce polling rate to 500ms.
// based off acr122u reader, see page 26 in api document.
// https://www.acs.com.hk/en/download-manual/419/API-ACR122U-2.04.pdf

#define PICC_OPERATING_PARAMS 0xDFu
BYTE PICC_OPERATING_PARAM_CMD[5] = {0xFFu, 0x00u, 0x51u, PICC_OPERATING_PARAMS, 0x00u};

// return bytes from device
#define PICC_SUCCESS 0x90u
#define PICC_ERROR 0x63u

static const BYTE UID_CMD[5] = {0xFFu, 0xCAu, 0x00u, 0x00u, 0x00u};

enum scard_atr_protocol
{
    SCARD_ATR_PROTOCOL_ISO14443_PART3 = 0x03,
    SCARD_ATR_PROTOCOL_ISO15693_PART3 = 0x0B,
    SCARD_ATR_PROTOCOL_FELICA_212K = 0x11,
    SCARD_ATR_PROTOCOL_FELICA_424K = 0x12,
};

// winscard_config_t WINSCARD_CONFIG;
SCARDCONTEXT hContext = 0;
SCARD_READERSTATE reader_states[2];
LPTSTR reader_name_slots[2] = {NULL, NULL};
int reader_count = 0;
LONG lRet = 0;

// Read one 16-byte block of a FeliCa card through the ACR122U's PN532.
// Uses the reader's Direct Transmit pseudo-APDU (FF 00 00 00 Lc ...) wrapping
// a FeliCa "Read Without Encryption" command (0x06) for a single service/block.
// Tries InDataExchange (D4 40) first, then InCommunicateThru (D4 42).
static bool felica_read_block(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pci, const BYTE idm[8], WORD service, BYTE block, BYTE out[16])
{
    static const BYTE pn532Cmds[2][3] = {{0xD4u, 0x40u, 0x01u}, {0xD4u, 0x42u, 0x00u}};
    static const BYTE pn532Lens[2] = {3, 2};

    for (int attempt = 0; attempt < 2; attempt++)
    {
        BYTE apdu[5 + 3 + 16];
        int n = 0;
        apdu[n++] = 0xFFu;
        apdu[n++] = 0x00u;
        apdu[n++] = 0x00u;
        apdu[n++] = 0x00u;
        apdu[n++] = 0x00u; // Lc, filled below
        for (int i = 0; i < pn532Lens[attempt]; i++)
            apdu[n++] = pn532Cmds[attempt][i];
        apdu[n++] = 0x10u; // FeliCa frame length (16 bytes incl. this byte)
        apdu[n++] = 0x06u; // Read Without Encryption
        memcpy(&apdu[n], idm, 8);
        n += 8;
        apdu[n++] = 0x01u;                  // number of services
        apdu[n++] = (BYTE)(service & 0xFF); // service code, little endian
        apdu[n++] = (BYTE)(service >> 8);
        apdu[n++] = 0x01u;  // number of blocks
        apdu[n++] = 0x80u;  // 2-byte block list element
        apdu[n++] = block;
        apdu[4] = (BYTE)(n - 5);

        BYTE rx[MAX_APDU_SIZE];
        DWORD rxLen = sizeof(rx);
        LONG ret = SCardTransmit(hCard, pci, apdu, (DWORD)n, NULL, rx, &rxLen);
        if (ret != SCARD_S_SUCCESS)
        {
            printWarning("%s (%s): FeliCa read (attempt %d) transmit failed: 0x%08X\n", __func__, module, attempt + 1, ret);
            continue;
        }

        // Expected: D5 41|43 00 | LEN 07 IDm(8) ST1 ST2 NBLK DATA(16) | 90 00
        if (rxLen < 3 + 13 + 16 + 2 || rx[0] != 0xD5u || rx[2] != 0x00u || rx[4] != 0x07u)
        {
            printWarning("%s (%s): FeliCa read (attempt %d) unexpected response, len %lu, first bytes %02X %02X %02X\n",
                         __func__, module, attempt + 1, (unsigned long)rxLen, rxLen > 0 ? rx[0] : 0, rxLen > 1 ? rx[1] : 0, rxLen > 2 ? rx[2] : 0);
            continue;
        }

        BYTE st1 = rx[13], st2 = rx[14];
        if (st1 != 0x00u || st2 != 0x00u)
        {
            printWarning("%s (%s): FeliCa read rejected by card, status %02X %02X\n", __func__, module, st1, st2);
            return false;
        }

        memcpy(out, &rx[16], 16);
        return true;
    }

    return false;
}

void scard_poll(uint8_t *buf, char *accessCode, SCARDCONTEXT _hContext, LPCTSTR _readerName, uint8_t unit_no)
{
    printInfo("%s (%s): Update on reader : %s\n", __func__, module, reader_states[unit_no].szReader);
    // Connect to the smart card.
    LONG lRet = 0;
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;
    for (int retry = 0; retry < 100; retry++) // retry times has to be increased since poll rate is set to 500ms
    {
        if ((lRet = SCardConnect(_hContext, _readerName, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol)) == SCARD_S_SUCCESS)
            break;

        Sleep(20);
    }

    if (lRet != SCARD_S_SUCCESS)
    {
        printError("%s (%s): Error connecting to the card: 0x%08X\n", __func__, module, lRet);
        return;
    }

    // set the reader params
    lRet = 0;
    LPCSCARD_IO_REQUEST pci = dwActiveProtocol == SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0;
    DWORD cbRecv = MAX_APDU_SIZE;
    BYTE pbRecv[MAX_APDU_SIZE];

    // Read ATR to determine card type.
    TCHAR szReader[200];
    DWORD cchReader = 200;
    BYTE atr[32];
    DWORD cByteAtr = 32;
    lRet = SCardStatus(hCard, szReader, &cchReader, NULL, NULL, atr, &cByteAtr);
    if (lRet != SCARD_S_SUCCESS)
    {
        printError("%s (%s): Error getting card status: 0x%08X\n", __func__, module, lRet);
        return;
    }

    // Only care about 20-byte ATRs returned by arcade-type smart cards
    if (cByteAtr != 20)
    {
        printError("%s (%s): Ignoring card with len(%d) = %02X (%08X)\n", __func__, module, cByteAtr, atr, cByteAtr);
        return;
    }

    printInfo("%s (%s): atr Return: len(%d) = %02X (%08X)\n", __func__, module, cByteAtr, atr, cByteAtr);

    // Figure out if we should reverse the UID returned by the card based on the ATR protocol
    BYTE cardProtocol = atr[12];
    BOOL shouldReverseUid = false;
    if (cardProtocol == SCARD_ATR_PROTOCOL_ISO15693_PART3)
    {
        printWarning("%s (%s): Card protocol: ISO15693_PART3\n", __func__, module);
        shouldReverseUid = true;
    }

    else if (cardProtocol == SCARD_ATR_PROTOCOL_ISO14443_PART3)
        printWarning("%s (%s): Card protocol: ISO14443_PART3\n", __func__, module);

    else if (cardProtocol == SCARD_ATR_PROTOCOL_FELICA_212K)
        printWarning("%s (%s): Card protocol: FELICA_212K\n", __func__, module);

    else if (cardProtocol == SCARD_ATR_PROTOCOL_FELICA_424K)
        printWarning("%s (%s): Card protocol: FELICA_424K\n", __func__, module);

    else
    {
        printError("%s (%s): Unknown NFC Protocol: 0x%02X\n", __func__, module, cardProtocol);
        return;
    }

    // Read UID
    cbRecv = MAX_APDU_SIZE;
    if ((lRet = SCardTransmit(hCard, pci, UID_CMD, sizeof(UID_CMD), NULL, pbRecv, &cbRecv)) != SCARD_S_SUCCESS)
    {
        printError("%s (%s): Error querying card UID: 0x%08X\n", __func__, module, lRet);
        return;
    }

    if (cbRecv > 1 && pbRecv[0] == PICC_ERROR)
    {
        printError("%s (%s): UID query failed\n", __func__, module);
        return;
    }

    // Amusement IC (FeliCa): try to read the printed access code from SPAD0 (block 0x00, service 0x000B)
    accessCode[0] = '\0';
    if (readAccessCode && (cardProtocol == SCARD_ATR_PROTOCOL_FELICA_212K || cardProtocol == SCARD_ATR_PROTOCOL_FELICA_424K) && cbRecv >= 8)
    {
        BYTE idm[8];
        memcpy(idm, pbRecv, 8);
        BYTE spad0[16];
        if (felica_read_block(hCard, pci, idm, 0x000Bu, 0x00u, spad0))
        {
            printInfo("%s (%s): SPAD0 raw: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", __func__, module,
                      spad0[0], spad0[1], spad0[2], spad0[3], spad0[4], spad0[5], spad0[6], spad0[7],
                      spad0[8], spad0[9], spad0[10], spad0[11], spad0[12], spad0[13], spad0[14], spad0[15]);
            char code[21];
            if (spad0_access_code(spad0, code))
            {
                memcpy(accessCode, code, 21);
                printWarning("%s (%s): Access code from card: %s\n", __func__, module, accessCode);
            }
            else
                printWarning("%s (%s): SPAD0 has no valid access code, falling back to IDm\n", __func__, module);
        }
        else
            printWarning("%s (%s): Could not read SPAD0, falling back to IDm\n", __func__, module);
    }

    if ((lRet = SCardDisconnect(hCard, SCARD_LEAVE_CARD)) != SCARD_S_SUCCESS)
        printError("%s (%s): Failed SCardDisconnect: 0x%08X\n", __func__, module, lRet);

    if (cbRecv < 8)
    {
        printWarning("%s (%s): Padding card uid to 8 bytes\n", __func__, module);
        memset(&pbRecv[cbRecv], 0, 8 - cbRecv);
    }
    else if (cbRecv > 8)
        printWarning("%s (%s): taking first 8 bytes of len(uid) = %02X\n", __func__, module, cbRecv);

    // Copy UID to struct, reversing if necessary
    card_info_t card_info;
    if (shouldReverseUid)
        for (DWORD i = 0; i < 8; i++)
            card_info.uid[i] = pbRecv[7 - i];
    else
        memcpy(card_info.uid, pbRecv, 8);

    for (int i = 0; i < 8; ++i)
        buf[i] = card_info.uid[i];
}

void scard_clear(uint8_t unitNo)
{
    card_info_t empty_cardinfo;
}

void scard_update(uint8_t *buf, char *accessCode)
{
    if (reader_count < 1)
    {
        return;
    }

    lRet = SCardGetStatusChange(hContext, readCooldown, reader_states, reader_count);
    if (lRet == SCARD_E_TIMEOUT)
    {
        return;
    }
    else if (lRet != SCARD_S_SUCCESS)
    {
        printError("%s (%s): Failed SCardGetStatusChange: 0x%08X\n", __func__, module, lRet);
        return;
    }

    for (uint8_t unit_no = 0; unit_no < reader_count; unit_no++)
    {
        if (!(reader_states[unit_no].dwEventState & SCARD_STATE_CHANGED))
            continue;

        DWORD newState = reader_states[unit_no].dwEventState ^ SCARD_STATE_CHANGED;
        bool wasCardPresent = (reader_states[unit_no].dwCurrentState & SCARD_STATE_PRESENT) > 0;
        if (newState & SCARD_STATE_UNAVAILABLE)
        {
            printWarning("%s (%s): New card state: unavailable\n", __func__, module);
            Sleep(readCooldown);
        }
        else if (newState & SCARD_STATE_EMPTY)
        {
            printWarning("%s (%s): New card state: empty\n", __func__, module);
            scard_clear(unit_no);
        }
        else if (newState & SCARD_STATE_PRESENT && !wasCardPresent)
        {
            printInfo("%s (%s): New card state: present\n", __func__, module);
            scard_poll(buf, accessCode, hContext, reader_states[unit_no].szReader, unit_no);
        }

        reader_states[unit_no].dwCurrentState = reader_states[unit_no].dwEventState;
    }

    return;
}

bool scard_init()
{
    if ((lRet = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext)) != SCARD_S_SUCCESS)
    {
        //  log_warning("scard", "failed to establish SCard context: {}", bin2hex(&lRet, sizeof(LONG)));
        return lRet;
    }

    LPCTSTR reader = NULL;

    int readerNameLen = 0;

    // get list of readers
    LPTSTR reader_list = NULL;
    auto pcchReaders = SCARD_AUTOALLOCATE;
    lRet = SCardListReaders(hContext, NULL, (LPTSTR)&reader_list, &pcchReaders);

    int slot0_idx = -1;
    int slot1_idx = -1;
    int readerCount = 0;
    switch (lRet)
    {
    case SCARD_E_NO_READERS_AVAILABLE:
        printError("%s (%s): No readers available\n", __func__, module);
        return FALSE;

    case SCARD_S_SUCCESS:

        // So WinAPI has this terrible "multi-string" concept wherein you have a list
        // of null-terminated strings, terminated by a double-null.
        for (reader = reader_list; *reader; reader = reader + lstrlen(reader) + 1)
        {
            printInfo("%s (%s): Found reader: %s\n", __func__, module, reader);
            readerCount++;

            // Connect to reader and send PICC operating params command
            LONG lRet = 0;
            SCARDHANDLE hCard;
            DWORD dwActiveProtocol;
            lRet = SCardConnect(hContext, reader, SCARD_SHARE_DIRECT, 0, &hCard, &dwActiveProtocol);
            if (lRet != SCARD_S_SUCCESS)
            {
                printError("%s (%s): Error connecting to the reader: 0x%08X\n", __func__, module, lRet);
                continue;
            }
            printInfo("%s (%s): Connected to reader: %s, sending PICC operating params command\n", __func__, module, reader);

            // set the reader params
            lRet = 0;
            DWORD cbRecv = MAX_APDU_SIZE;
            BYTE pbRecv[MAX_APDU_SIZE];
            lRet = SCardControl(hCard, SCARD_CTL_CODE(3500), PICC_OPERATING_PARAM_CMD, sizeof(PICC_OPERATING_PARAM_CMD), pbRecv, cbRecv, &cbRecv);
            Sleep(100);
            if (lRet != SCARD_S_SUCCESS)
            {
                printError("%s (%s): Error setting PICC params: 0x%08X\n", __func__, module, lRet);
                return FALSE;
            }

            if (cbRecv > 2 && pbRecv[0] != PICC_SUCCESS && pbRecv[1] != PICC_OPERATING_PARAMS)
            {
                printError("%s (%s): PICC params not valid 0x%02X != 0x%02X\n", __func__, module, pbRecv[1], PICC_OPERATING_PARAMS);
                return FALSE;
            }

            // Disconnect from reader
            if ((lRet = SCardDisconnect(hCard, SCARD_LEAVE_CARD)) != SCARD_S_SUCCESS)
            {
                printError("%s (%s): Failed SCardDisconnect: 0x%08X\n", __func__, module, lRet);
            }
            else
            {
                printInfo("%s (%s): Disconnected from reader: %s, this is expected behavior\n", __func__, module, reader);
            }

            break;
        }

        // If we have at least two readers, assign readers to slots as necessary.
        if (readerCount >= 2)
        {
            if (slot1_idx != 0)
                slot0_idx = 0;
            if (slot0_idx != 1)
                slot1_idx = 1;
        }

        // if the reader count is 1 and no reader was set, set first reader
        if (readerCount == 1 && slot0_idx < 0 && slot1_idx < 0)
            slot0_idx = 0;

        // If we somehow only found slot 1, promote slot 1 to slot 0.
        if (slot0_idx < 0 && slot1_idx >= 0)
        {
            slot0_idx = slot1_idx;
            slot1_idx = -1;
        }

        // Extract the relevant names from the multi-string.
        int i;
        for (i = 0, reader = reader_list; *reader; reader = reader + lstrlen(reader) + 1, i++)
        {
            if (slot0_idx == i)
            {
                readerNameLen = lstrlen(reader);
                reader_name_slots[0] = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(TCHAR) * (readerNameLen + 1));
                memcpy(reader_name_slots[0], &reader[0], (size_t)(readerNameLen + 1));
            }
            if (slot1_idx == i)
            {
                readerNameLen = lstrlen(reader);
                reader_name_slots[1] = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(TCHAR) * (readerNameLen + 1));
                memcpy(reader_name_slots[1], &reader[0], (size_t)(readerNameLen + 1));
            }
            break;
        }

        if (reader_name_slots[0])
            printInfo("%s (%s): Using reader slot 0: %s\n", __func__, module, reader_name_slots[0]);

        if (reader_name_slots[1])
            printInfo("%s (%s): Using reader slot 1: %s\n", __func__, module, reader_name_slots[1]);

        reader_count = reader_name_slots[1] ? 2 : 1;

        memset(&reader_states[0], 0, sizeof(SCARD_READERSTATE));
        reader_states[0].szReader = reader_name_slots[0];

        memset(&reader_states[1], 0, sizeof(SCARD_READERSTATE));
        reader_states[1].szReader = reader_name_slots[1];
        return TRUE;

    default:
        printWarning("%s (%s): Failed SCardListReaders: 0x%08X\n", __func__, module, lRet);
        return FALSE;
    }

    if (reader_list)
    {
        SCardFreeMemory(hContext, reader_list);
    }
}