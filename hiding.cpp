/*
 * =====================================================================
 *  DATA HIDING AND MASKING - Demo in C++
 *  No external libraries needed. Pure C++ OOP implementation.
 *
 *  Compile:  g++ hiding.cpp -o hiding
 *  Run:      ./hiding
 * =====================================================================
 *
 *  WHAT IS DATA HIDING?
 *  --------------------
 *  Data hiding means concealing sensitive information so it cannot
 *  be read directly. This file implements:
 *
 *    1. XOR Cipher     - scramble data with a key (reversible)
 *    2. Caesar Cipher  - shift each character by a fixed number
 *    3. Bit Masking    - hide specific bits using bitmasks
 *    4. Steganography  - hide a message inside another message
 *
 *  The C++ version organises each technique into its own class,
 *  making the code modular and easy to reuse.
 * =====================================================================
 */

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>

/* ================================================================
 *  CLASS 1: XorCipher
 *
 *  How it works:
 *    - Each character of the message is XOR'd with the key character
 *    - XOR is its own inverse: (A XOR B) XOR B = A
 *    - Same encrypt() function is used for both hiding and revealing
 *
 *  Example:
 *    Key     = "KEY"
 *    Message = "Hello"
 *    H XOR K = scrambled, scrambled XOR K = H  (recovered)
 * ================================================================ */
class XorCipher {
private:
    std::string key;

public:
    /* Constructor: set the secret key */
    XorCipher(const std::string &k) : key(k) {}

    /*
     * apply() - hides OR reveals text using XOR
     * The same function does both: call it once to hide,
     * call it again with the same key to reveal.
     */
    std::string apply(const std::string &text) const {
        std::string result = text;
        int keyLen = key.length();

        for (int i = 0; i < (int)text.length(); i++) {
            /* XOR each character; key repeats if shorter than text */
            result[i] = text[i] ^ key[i % keyLen];
        }
        return result;
    }

    /* Convert a string to a hex representation for display */
    std::string toHex(const std::string &data) const {
        std::stringstream ss;
        for (unsigned char c : data) {
            ss << std::hex << std::uppercase
               << std::setw(2) << std::setfill('0')
               << (int)c << ' ';
        }
        return ss.str();
    }
};


/* ================================================================
 *  CLASS 2: CaesarCipher
 *
 *  How it works:
 *    - Each letter is shifted forward by 'shift' positions in alphabet
 *    - 'A' + 3 = 'D',  'Z' + 3 = 'C' (wraps around)
 *    - Non-letters (digits, spaces, punctuation) are left unchanged
 *    - Decrypt: shift in the opposite direction
 *
 *  Example (shift = 3):
 *    "Hello" -> "Khoor"
 *    "Khoor" -> "Hello" (decrypted)
 * ================================================================ */
class CaesarCipher {
private:
    int shift;   /* how many positions to shift each letter */

public:
    /* Constructor: set the shift amount (1-25) */
    CaesarCipher(int s) : shift(s % 26) {}

    /* encrypt() - shifts letters forward */
    std::string encrypt(const std::string &text) const {
        std::string result = text;
        for (char &c : result) {
            if (c >= 'A' && c <= 'Z') {
                /* Uppercase letter: shift and wrap around at 'Z' */
                c = (char)(((c - 'A' + shift) % 26) + 'A');
            } else if (c >= 'a' && c <= 'z') {
                /* Lowercase letter: shift and wrap around at 'z' */
                c = (char)(((c - 'a' + shift) % 26) + 'a');
            }
            /* Digits, spaces, punctuation: leave unchanged */
        }
        return result;
    }

    /* decrypt() - shifts letters backward (reverse of encrypt) */
    std::string decrypt(const std::string &text) const {
        std::string result = text;
        for (char &c : result) {
            if (c >= 'A' && c <= 'Z') {
                /* Add 26 before subtracting to avoid negative modulo */
                c = (char)(((c - 'A' - shift + 26) % 26) + 'A');
            } else if (c >= 'a' && c <= 'z') {
                c = (char)(((c - 'a' - shift + 26) % 26) + 'a');
            }
        }
        return result;
    }

    int getShift() const { return shift; }
};


/* ================================================================
 *  CLASS 3: BitMasker
 *
 *  How it works:
 *    - A "bitmask" is a number where certain bits are set (1) or clear (0)
 *    - Masking operations:
 *        AND mask: clears bits    (set bit to 0 in mask to hide it)
 *        OR  mask: sets bits      (force certain bits to 1)
 *        XOR mask: flips bits     (toggle specific bits)
 *
 *  Example:
 *    Value = 0b10110110  (182)
 *    Mask  = 0b11110000  (0xF0)
 *    AND   = 0b10110000  (only top 4 bits remain; bottom 4 hidden)
 *
 *  Real-world use: hide permission flags, sensor values, port numbers
 * ================================================================ */
class BitMasker {
public:

    /* andMask() - keeps only bits that are SET in the mask */
    static unsigned int andMask(unsigned int value, unsigned int mask) {
        return value & mask;    /* bit is kept if mask bit = 1, else cleared */
    }

    /* orMask() - forces certain bits to be 1 */
    static unsigned int orMask(unsigned int value, unsigned int mask) {
        return value | mask;    /* bit is forced to 1 where mask bit = 1 */
    }

    /* xorMask() - flips bits where mask is 1 */
    static unsigned int xorMask(unsigned int value, unsigned int mask) {
        return value ^ mask;    /* bit is flipped where mask bit = 1 */
    }

    /* Print a number in binary (8-bit format) */
    static std::string toBinary8(unsigned int value) {
        std::string result = "";
        for (int i = 7; i >= 0; i--) {
            result += ((value >> i) & 1) ? '1' : '0';
        }
        return result;
    }

    /* Print a number in binary (32-bit format) */
    static std::string toBinary32(unsigned int value) {
        std::string result = "";
        for (int i = 31; i >= 0; i--) {
            result += ((value >> i) & 1) ? '1' : '0';
            if (i % 4 == 0 && i > 0) result += ' ';
        }
        return result;
    }
};


/* ================================================================
 *  CLASS 4: TextSteganography
 *
 *  How it works:
 *    - Hide a secret message inside a "cover" text
 *    - We use a simple approach: the FIRST LETTER of each word in
 *      the cover text spells out the hidden message (an acrostic)
 *    - To reveal: collect the first letter of every word
 *
 *  Example:
 *    Secret: "HI"
 *    We pick/arrange words so:
 *      Word 1 starts with 'H' -> "Hello"
 *      Word 2 starts with 'I' -> "Indeed"
 *      Cover: "Hello Indeed friend"
 *    Extract: H + I = "HI"
 *
 *  Alternative method included: embedding via a delimiter character
 * ================================================================ */
class TextSteganography {
private:
    char delimiter;   /* special character to mark hidden data */

public:
    TextSteganography(char delim = '\x01') : delimiter(delim) {}

    /*
     * hide() - embeds secret characters into cover text
     * After every cover character, a hidden character is inserted
     * preceded by the delimiter marker.
     */
    std::string hide(const std::string &cover, const std::string &secret) const {
        std::string result = "";
        int si = 0;   /* index into secret */

        for (int ci = 0; ci < (int)cover.length(); ci++) {
            result += cover[ci];   /* add one cover character */

            /* Embed one secret character (if any remain) */
            if (si < (int)secret.length()) {
                result += delimiter;       /* marker: hidden data follows */
                result += secret[si++];    /* the hidden character */
            }
        }
        return result;
    }

    /*
     * reveal() - extracts the hidden message from stego text
     * Looks for the delimiter character and collects the byte after it.
     */
    std::string reveal(const std::string &stegoText) const {
        std::string secret = "";

        for (int i = 0; i < (int)stegoText.length(); i++) {
            if (stegoText[i] == delimiter && i + 1 < (int)stegoText.length()) {
                secret += stegoText[i + 1];  /* collect hidden character */
                i++;                          /* skip the hidden character */
            }
        }
        return secret;
    }

    /*
     * acrosticHide() - creates an acrostic: first letter of each word
     * spells the secret message.
     * secret  : the message to encode (letters only)
     * words   : array of words (must have at least secret.length() words)
     * Returns the cover sentence built from those words.
     */
    std::string acrosticReveal(const std::string &sentence) const {
        std::string secret = "";
        bool newWord = true;

        for (char c : sentence) {
            if (c == ' ') {
                newWord = true;         /* next character starts a new word */
            } else if (newWord) {
                secret += c;            /* first letter of this word */
                newWord = false;
            }
        }
        return secret;
    }
};


/* ================================================================
 *  MAIN - Run all demonstrations
 * ================================================================ */
int main() {
    std::cout << "=====================================================\n"
              << "    DATA HIDING DEMO (C++)                         \n"
              << "=====================================================\n\n";

    /* --------------------------------------------------------
     * DEMO 1: XOR Cipher
     * -------------------------------------------------------- */
    std::cout << "--- TECHNIQUE 1: XOR Cipher ---\n";

    XorCipher xor_cipher("SecretKey");
    std::string original = "Hello, Hidden World!";

    std::string hidden   = xor_cipher.apply(original);
    std::string revealed = xor_cipher.apply(hidden);       /* same call = decrypt */

    std::cout << "Original Message : " << original  << "\n"
              << "XOR Key          : SecretKey\n"
              << "Hidden (hex)     : " << xor_cipher.toHex(hidden) << "\n"
              << "Revealed Message : " << revealed  << "\n\n";

    /* --------------------------------------------------------
     * DEMO 2: Caesar Cipher
     * -------------------------------------------------------- */
    std::cout << "--- TECHNIQUE 2: Caesar Cipher ---\n";

    CaesarCipher caesar(13);   /* ROT-13: shift by 13 */
    std::string plaintext  = "Meet me at midnight!";
    std::string encrypted  = caesar.encrypt(plaintext);
    std::string decrypted  = caesar.decrypt(encrypted);

    std::cout << "Original  : " << plaintext  << "\n"
              << "Shift     : " << caesar.getShift() << " (ROT-13)\n"
              << "Encrypted : " << encrypted  << "\n"
              << "Decrypted : " << decrypted  << "\n\n";

    /* --------------------------------------------------------
     * DEMO 3: Bit Masking
     * -------------------------------------------------------- */
    std::cout << "--- TECHNIQUE 3: Bit Masking ---\n";

    unsigned int value = 0b10110110;    /* = 182 = 0xB6 */
    unsigned int mask  = 0b11110000;    /* = 240 = 0xF0 */

    unsigned int andResult = BitMasker::andMask(value, mask);
    unsigned int orResult  = BitMasker::orMask (value, mask);
    unsigned int xorResult = BitMasker::xorMask(value, mask);

    std::cout << "Value     : " << BitMasker::toBinary8(value)
              << "  (" << value << ")\n"
              << "Mask      : " << BitMasker::toBinary8(mask)
              << "  (" << mask  << ")\n"
              << "AND result: " << BitMasker::toBinary8(andResult)
              << "  (" << andResult << ")  <- bottom 4 bits hidden\n"
              << "OR  result: " << BitMasker::toBinary8(orResult)
              << "  (" << orResult  << ")  <- top 4 bits forced to 1\n"
              << "XOR result: " << BitMasker::toBinary8(xorResult)
              << "  (" << xorResult << ")  <- top 4 bits flipped\n\n";

    /* ---- Real-world example: hide lower byte of a 32-bit value ---- */
    unsigned int ipAddr     = 0xC0A80101;  /* 192.168.1.1 */
    unsigned int hideMask   = 0xFFFFFF00;  /* hide last octet */
    unsigned int maskedIP   = BitMasker::andMask(ipAddr, hideMask);

    std::cout << "IP Address (hidden last octet):\n"
              << "  Original : " << BitMasker::toBinary32(ipAddr)   << "\n"
              << "  Mask     : " << BitMasker::toBinary32(hideMask) << "\n"
              << "  Result   : " << BitMasker::toBinary32(maskedIP) << "\n\n";

    /* --------------------------------------------------------
     * DEMO 4: Text Steganography
     * -------------------------------------------------------- */
    std::cout << "--- TECHNIQUE 4: Text Steganography ---\n\n";

    TextSteganography steg;

    /* Method A: delimiter embedding */
    std::cout << "Method A - Delimiter Embedding:\n";
    std::string cover     = "The sun rises early every morning";
    std::string secretMsg = "HIDE";

    std::string stegoText = steg.hide(cover, secretMsg);
    std::string extracted = steg.reveal(stegoText);

    std::cout << "Cover Text       : " << cover      << "\n"
              << "Secret Message   : " << secretMsg  << "\n"
              << "Stego Text length: " << stegoText.length()
              << " bytes (cover has hidden data embedded)\n"
              << "Extracted Secret : " << extracted  << "\n\n";

    /* Method B: acrostic (first letter of each word) */
    std::cout << "Method B - Acrostic (first letter of each word):\n";
    std::string acrosticSentence =
        "Nightfall over weather brings every night reality";

    std::string acrosticSecret = steg.acrosticReveal(acrosticSentence);

    std::cout << "Sentence         : " << acrosticSentence << "\n"
              << "Hidden Message   : " << acrosticSecret
              << "  (first letter of each word)\n";

    std::cout << "\n=====================================================\n"
              << "All demonstrations complete.\n"
              << "=====================================================\n";

    return 0;
}
