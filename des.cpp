/*
 * =====================================================================
 *  DES (Data Encryption Standard) - Simple Demo in C++
 *  No external libraries needed. Pure C++ OOP implementation.
 *
 *  Compile:  g++ des.cpp -o des
 *  Run:      ./des
 * =====================================================================
 *
 *  HOW DES WORKS:
 *  --------------
 *  DES is a symmetric block cipher:
 *    - Block size : 64 bits (8 bytes)
 *    - Key size   : 56 bits (stored in 64 bits; every 8th bit is parity)
 *    - Structure  : 16 rounds of Feistel cipher
 *
 *  Each round:
 *    1. Split 64-bit block into Left (32 bits) and Right (32 bits)
 *    2. new_Right = Left XOR F(Right, SubKey)
 *    3. new_Left  = old Right
 *
 *  F-function:
 *    1. Expand Right from 32 to 48 bits
 *    2. XOR with 48-bit SubKey
 *    3. Pass through 8 S-Boxes (6 bits in -> 4 bits out each)
 *    4. Apply permutation P
 *
 *  Decryption = same algorithm with subkeys in reverse order.
 * =====================================================================
 */

#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdint>

/* ================================================================
 *  DES LOOKUP TABLES
 * ================================================================ */

static const int IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const int FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25
};

static const int E[48] = {
    32,1,2,3,4,5,  4,5,6,7,8,9,  8,9,10,11,12,13,
    12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
};

static const int P[32] = {
    16,7,20,21, 29,12,28,17,  1,15,23,26,  5,18,31,10,
     2,8,24,14, 32,27,3,9,   19,13,30,6,  22,11,4,25
};

static const int PC1[56] = {
    57,49,41,33,25,17,9,  1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
};

static const int PC2[48] = {
    14,17,11,24,1,5,   3,28,15,6,21,10,
    23,19,12,4,26,8,  16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
};

static const int SHIFTS[16] = { 1,1,2,2, 2,2,2,2, 1,2,2,2, 2,2,2,1 };

static const int SBOX[8][4][16] = {
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
     {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
     {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
     {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
     {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
     {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
     {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
     {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

/* ================================================================
 *  DES CLASS
 * ================================================================ */
class DES {
private:
    uint64_t subkeys[16];   // 16 round subkeys

    /* --- Bit helpers --- */
    int getBit64(uint64_t val, int n) const {
        return (val >> (64 - n)) & 1;
    }
    int getBit32(uint32_t val, int n) const {
        return (val >> (32 - n)) & 1;
    }

    /* --- Apply a permutation table to 64-bit value --- */
    uint64_t permute64(uint64_t val, const int *table, int size) const {
        uint64_t result = 0;
        for (int i = 0; i < size; i++)
            result = (result << 1) | getBit64(val, table[i]);
        return result;
    }

    /* --- Apply a permutation table to 32-bit value --- */
    uint32_t permute32(uint32_t val, const int *table, int size) const {
        uint32_t result = 0;
        for (int i = 0; i < size; i++)
            result = (result << 1) | getBit32(val, table[i]);
        return result;
    }

    /* --- Generate 16 round subkeys from the 64-bit key --- */
    void generateSubkeys(uint64_t key) {
        // Apply PC1: reduce 64-bit key to 56 bits
        uint64_t permKey = permute64(key, PC1, 56);

        // Split into two 28-bit halves
        uint32_t C = (permKey >> 28) & 0x0FFFFFFF;
        uint32_t D = permKey & 0x0FFFFFFF;

        for (int round = 0; round < 16; round++) {
            // Rotate each half left by SHIFTS[round]
            int s = SHIFTS[round];
            C = ((C << s) | (C >> (28 - s))) & 0x0FFFFFFF;
            D = ((D << s) | (D >> (28 - s))) & 0x0FFFFFFF;

            // Combine and apply PC2 to get 48-bit subkey
            uint64_t CD = ((uint64_t)C << 28) | D;
            subkeys[round] = 0;
            for (int i = 0; i < 48; i++) {
                int bit = (CD >> (56 - PC2[i])) & 1;
                subkeys[round] = (subkeys[round] << 1) | bit;
            }
        }
    }

    /* --- F-function: core of each DES round --- */
    uint32_t F(uint32_t R, uint64_t subkey) const {
        // 1. Expand R from 32 to 48 bits
        uint64_t expanded = 0;
        for (int i = 0; i < 48; i++)
            expanded = (expanded << 1) | getBit32(R, E[i]);

        // 2. XOR with subkey
        uint64_t xored = expanded ^ subkey;

        // 3. S-Box substitution (8 groups of 6 bits -> 4 bits each)
        uint32_t sboxOut = 0;
        for (int i = 0; i < 8; i++) {
            int sixBits = (xored >> (42 - 6 * i)) & 0x3F;
            int row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
            int col = (sixBits >> 1) & 0x0F;
            sboxOut = (sboxOut << 4) | SBOX[i][row][col];
        }

        // 4. Permutation P
        return permute32(sboxOut, P, 32);
    }

public:
    /* Constructor: set key and generate subkeys */
    DES(uint64_t key) {
        generateSubkeys(key);
    }

    /* --- Encrypt a 64-bit block --- */
    uint64_t encrypt(uint64_t block) const {
        // Initial Permutation
        uint64_t perm = permute64(block, IP, 64);
        uint32_t L = (uint32_t)(perm >> 32);
        uint32_t R = (uint32_t)(perm & 0xFFFFFFFF);

        // 16 Feistel rounds (subkeys in forward order)
        for (int round = 0; round < 16; round++) {
            uint32_t newR = L ^ F(R, subkeys[round]);
            L = R;
            R = newR;
        }

        // Final Permutation (with L and R swapped)
        uint64_t combined = ((uint64_t)R << 32) | L;
        return permute64(combined, FP, 64);
    }

    /* --- Decrypt a 64-bit block --- */
    uint64_t decrypt(uint64_t block) const {
        // Initial Permutation
        uint64_t perm = permute64(block, IP, 64);
        uint32_t L = (uint32_t)(perm >> 32);
        uint32_t R = (uint32_t)(perm & 0xFFFFFFFF);

        // 16 Feistel rounds (subkeys in REVERSE order for decryption)
        for (int round = 15; round >= 0; round--) {
            uint32_t newR = L ^ F(R, subkeys[round]);
            L = R;
            R = newR;
        }

        // Final Permutation
        uint64_t combined = ((uint64_t)R << 32) | L;
        return permute64(combined, FP, 64);
    }
};

/* ================================================================
 *  HELPER FUNCTIONS
 * ================================================================ */
static uint64_t bytesToUint64(const uint8_t bytes[8]) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) val = (val << 8) | bytes[i];
    return val;
}

static void uint64ToBytes(uint64_t val, uint8_t bytes[8]) {
    for (int i = 7; i >= 0; i--) { bytes[i] = val & 0xFF; val >>= 8; }
}

static void printHex(const std::string &label, const uint8_t *data, int len) {
    printf("%-22s: ", label.c_str());
    for (int i = 0; i < len; i++) printf("%02X ", data[i]);
    printf("\n");
}

/* ================================================================
 *  MAIN - Demo
 * ================================================================ */
int main() {
    std::cout << "===========================================\n"
              << "   DES Encryption Demo (Pure C++)         \n"
              << "===========================================\n\n";

    // 8-byte key and plaintext
    uint8_t key[8]       = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 };
    uint8_t plaintext[8] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF };

    printHex("Key (8 bytes)",       key,       8);
    printHex("Plaintext (8 bytes)", plaintext, 8);
    std::cout << '\n';

    // Create DES object with key
    uint64_t keyVal = bytesToUint64(key);
    DES des(keyVal);

    // Encrypt
    uint64_t ptVal = bytesToUint64(plaintext);
    uint64_t ctVal = des.encrypt(ptVal);

    uint8_t ciphertext[8], decrypted[8];
    uint64ToBytes(ctVal, ciphertext);
    printHex("Ciphertext (8 bytes)", ciphertext, 8);

    // Decrypt
    uint64_t decVal = des.decrypt(ctVal);
    uint64ToBytes(decVal, decrypted);
    printHex("Decrypted  (8 bytes)", decrypted, 8);

    // Verify
    std::cout << '\n';
    if (memcmp(plaintext, decrypted, 8) == 0)
        std::cout << "SUCCESS: Decrypted text matches original plaintext!\n";
    else
        std::cout << "FAILED: Mismatch!\n";

    std::cout << "\nNOTE: DES uses a 56-bit key and is no longer secure.\n"
              << "      Use AES for any real application.\n";

    return 0;
}
