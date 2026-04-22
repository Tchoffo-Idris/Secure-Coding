/*
 * =====================================================================
 *  AES-128 (Advanced Encryption Standard) - Simple Demo in C
 *  No external libraries needed. Pure C implementation.
 *
 *  Compile:  gcc aes.c -o aes
 *  Run:      ./aes
 * =====================================================================
 *
 *  HOW AES WORKS (Overview):
 *  --------------------------
 *  AES operates on a 4x4 grid of bytes called the "state".
 *  For AES-128: 128-bit block, 128-bit key, 10 rounds.
 *
 *  Each round (except the last) has 4 steps:
 *    1. SubBytes   - Replace each byte using the S-Box lookup table
 *    2. ShiftRows  - Rotate each row of the state left by different amounts
 *    3. MixColumns - Mix the bytes within each column (matrix multiply)
 *    4. AddRoundKey- XOR the state with the round key
 *
 *  The last round skips MixColumns.
 *
 *  Key Expansion: The 128-bit key is expanded into 11 round keys (44 words).
 * =====================================================================
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ================================================================
 *  AES S-BOX and INVERSE S-BOX
 *  Used in SubBytes step. Each byte is replaced by the value at
 *  that index in this table.
 * ================================================================ */
static const uint8_t SBOX[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

/* Inverse S-Box (used in decryption SubBytes) */
static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

/* Round constants for key expansion */
static const uint8_t RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

/* ================================================================
 *  GALOIS FIELD MULTIPLICATION (used in MixColumns)
 *  xtime() multiplies by 2 in GF(2^8)
 * ================================================================ */
static uint8_t xtime(uint8_t x) {
    /* Shift left by 1; if bit 7 was set, XOR with 0x1B (AES polynomial) */
    return (x << 1) ^ ((x >> 7) ? 0x1B : 0x00);
}

/* Multiply two bytes in GF(2^8) */
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t carry = a >> 7;
        a <<= 1;
        if (carry) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

/* ================================================================
 *  KEY EXPANSION
 *  Expands 16-byte key into 11 round keys (176 bytes total)
 * ================================================================ */
static void keyExpansion(const uint8_t key[16], uint8_t roundKeys[11][16]) {
    /* Copy the original key as round key 0 */
    memcpy(roundKeys[0], key, 16);

    /* We work with 32-bit words: 44 words total (4 per round key) */
    uint8_t w[44][4];
    for (int i = 0; i < 4; i++)
        memcpy(w[i], key + 4 * i, 4);

    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        memcpy(temp, w[i - 1], 4);

        if (i % 4 == 0) {
            /* RotWord: rotate left by 1 byte */
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2];
            temp[2] = temp[3]; temp[3] = t;

            /* SubWord: apply S-Box to each byte */
            for (int j = 0; j < 4; j++)
                temp[j] = SBOX[temp[j]];

            /* XOR with round constant */
            temp[0] ^= RCON[i / 4 - 1];
        }

        /* w[i] = w[i-4] XOR temp */
        for (int j = 0; j < 4; j++)
            w[i][j] = w[i - 4][j] ^ temp[j];
    }

    /* Pack words into round keys */
    for (int round = 1; round <= 10; round++)
        for (int i = 0; i < 4; i++)
            memcpy(roundKeys[round] + 4 * i, w[round * 4 + i], 4);
}

/* ================================================================
 *  AES ROUND OPERATIONS
 * ================================================================ */

/* AddRoundKey: XOR state with the current round key */
static void addRoundKey(uint8_t state[16], const uint8_t roundKey[16]) {
    for (int i = 0; i < 16; i++)
        state[i] ^= roundKey[i];
}

/* SubBytes: replace each byte using the S-Box */
static void subBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = SBOX[state[i]];
}

/* Inverse SubBytes: replace each byte using the Inverse S-Box */
static void invSubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = INV_SBOX[state[i]];
}

/*
 * ShiftRows: cyclically shift rows left
 *   Row 0: no shift
 *   Row 1: shift 1 left
 *   Row 2: shift 2 left
 *   Row 3: shift 3 left
 *
 * State is stored column-major:
 *   state[0] state[4] state[8]  state[12]
 *   state[1] state[5] state[9]  state[13]
 *   state[2] state[6] state[10] state[14]
 *   state[3] state[7] state[11] state[15]
 */
static void shiftRows(uint8_t state[16]) {
    uint8_t t;
    /* Row 1: shift left by 1 */
    t = state[1]; state[1]=state[5]; state[5]=state[9]; state[9]=state[13]; state[13]=t;
    /* Row 2: shift left by 2 */
    t = state[2]; state[2]=state[10]; state[10]=t;
    t = state[6]; state[6]=state[14]; state[14]=t;
    /* Row 3: shift left by 3 (= right by 1) */
    t = state[15]; state[15]=state[11]; state[11]=state[7]; state[7]=state[3]; state[3]=t;
}

/* Inverse ShiftRows: shift rows right */
static void invShiftRows(uint8_t state[16]) {
    uint8_t t;
    /* Row 1: shift right by 1 */
    t = state[13]; state[13]=state[9]; state[9]=state[5]; state[5]=state[1]; state[1]=t;
    /* Row 2: shift right by 2 */
    t = state[2]; state[2]=state[10]; state[10]=t;
    t = state[6]; state[6]=state[14]; state[14]=t;
    /* Row 3: shift right by 3 (= left by 1) */
    t = state[3]; state[3]=state[7]; state[7]=state[11]; state[11]=state[15]; state[15]=t;
}

/* MixColumns: mix bytes within each column */
static void mixColumns(uint8_t state[16]) {
    for (int col = 0; col < 4; col++) {
        uint8_t *s = state + col * 4;
        uint8_t s0=s[0], s1=s[1], s2=s[2], s3=s[3];
        s[0] = gmul(0x02,s0) ^ gmul(0x03,s1) ^ s2         ^ s3;
        s[1] = s0         ^ gmul(0x02,s1) ^ gmul(0x03,s2) ^ s3;
        s[2] = s0         ^ s1         ^ gmul(0x02,s2) ^ gmul(0x03,s3);
        s[3] = gmul(0x03,s0) ^ s1         ^ s2         ^ gmul(0x02,s3);
    }
}

/* Inverse MixColumns */
static void invMixColumns(uint8_t state[16]) {
    for (int col = 0; col < 4; col++) {
        uint8_t *s = state + col * 4;
        uint8_t s0=s[0], s1=s[1], s2=s[2], s3=s[3];
        s[0] = gmul(0x0E,s0)^gmul(0x0B,s1)^gmul(0x0D,s2)^gmul(0x09,s3);
        s[1] = gmul(0x09,s0)^gmul(0x0E,s1)^gmul(0x0B,s2)^gmul(0x0D,s3);
        s[2] = gmul(0x0D,s0)^gmul(0x09,s1)^gmul(0x0E,s2)^gmul(0x0B,s3);
        s[3] = gmul(0x0B,s0)^gmul(0x0D,s1)^gmul(0x09,s2)^gmul(0x0E,s3);
    }
}

/* ================================================================
 *  AES-128 ENCRYPT a single 16-byte block
 * ================================================================ */
static void aesEncrypt(const uint8_t plaintext[16], const uint8_t key[16],
                       uint8_t ciphertext[16]) {
    uint8_t roundKeys[11][16];
    keyExpansion(key, roundKeys);

    /* Copy plaintext into state */
    uint8_t state[16];
    memcpy(state, plaintext, 16);

    /* Initial round key addition */
    addRoundKey(state, roundKeys[0]);

    /* 9 main rounds */
    for (int round = 1; round <= 9; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys[round]);
    }

    /* Final round (no MixColumns) */
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys[10]);

    memcpy(ciphertext, state, 16);
}

/* ================================================================
 *  AES-128 DECRYPT a single 16-byte block
 * ================================================================ */
static void aesDecrypt(const uint8_t ciphertext[16], const uint8_t key[16],
                       uint8_t plaintext[16]) {
    uint8_t roundKeys[11][16];
    keyExpansion(key, roundKeys);

    uint8_t state[16];
    memcpy(state, ciphertext, 16);

    /* Start with last round key */
    addRoundKey(state, roundKeys[10]);

    /* 9 inverse rounds (in reverse order) */
    for (int round = 9; round >= 1; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys[round]);
        invMixColumns(state);
    }

    /* Final inverse round */
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys[0]);

    memcpy(plaintext, state, 16);
}

/* ================================================================
 *  HELPER: print bytes as hex
 * ================================================================ */
static void printHex(const char *label, const uint8_t *data, int len) {
    printf("%-20s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02X ", data[i]);
    printf("\n");
}

/* ================================================================
 *  MAIN - Demo
 * ================================================================ */
int main(void) {
    printf("===========================================\n");
    printf("   AES-128 Encryption Demo (Pure C)       \n");
    printf("===========================================\n\n");

    /* 16-byte (128-bit) key */
    uint8_t key[16] = {
        0x2B,0x7E,0x15,0x16, 0x28,0xAE,0xD2,0xA6,
        0xAB,0xF7,0x15,0x88, 0x09,0xCF,0x4F,0x3C
    };

    /* 16-byte (128-bit) plaintext */
    uint8_t plaintext[16] = {
        0x32,0x43,0xF6,0xA8, 0x88,0x5A,0x30,0x8D,
        0x31,0x31,0x98,0xA2, 0xE0,0x37,0x07,0x34
    };

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    printHex("Key (16 bytes)",       key,       16);
    printHex("Plaintext (16 bytes)", plaintext, 16);
    printf("\n");

    /* Encrypt */
    aesEncrypt(plaintext, key, ciphertext);
    printHex("Ciphertext (16 bytes)", ciphertext, 16);

    /* Decrypt */
    aesDecrypt(ciphertext, key, decrypted);
    printHex("Decrypted  (16 bytes)", decrypted, 16);

    /* Verify */
    printf("\n");
    if (memcmp(plaintext, decrypted, 16) == 0)
        printf("SUCCESS: Decrypted text matches original plaintext!\n");
    else
        printf("FAILED: Mismatch!\n");

    printf("\nExpected ciphertext: 39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32\n");
    printf("(This is the NIST FIPS-197 test vector for AES-128)\n");

    return 0;
}
