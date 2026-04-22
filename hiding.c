/*
 * =====================================================================
 *  DATA HIDING AND MASKING - Demo in C
 *  No external libraries needed. Pure C implementation.
 *
 *  Compile:  gcc hiding.c -o hiding
 *  Run:      ./hiding
 * =====================================================================
 *
 *  WHAT IS DATA HIDING?
 *  --------------------
 *  Data hiding means concealing sensitive information so it cannot
 *  be read directly. Examples:
 *    - Hiding a secret message inside a text (steganography)
 *    - XOR cipher: scramble data with a key so it looks random
 *
 *  WHAT IS DATA MASKING?
 *  ---------------------
 *  Data masking means replacing sensitive data with a fake but
 *  realistic-looking version. The original shape is kept but the
 *  real values are hidden. Examples:
 *    - Credit card: 4111 1111 1111 1111  ->  **** **** **** 1111
 *    - Email:       alice@gmail.com       ->  a***@gmail.com
 *    - Phone:       0677-123-456          ->  0677-***-***
 *    - Password:    mySecret123           ->  ************
 *
 *  This file demonstrates FOUR techniques:
 *    1. XOR Cipher         - hide data by XOR-ing with a key
 *    2. Credit Card Mask   - show only last 4 digits
 *    3. Email Mask         - hide middle characters of email
 *    4. Steganography      - hide a secret message inside another message
 * =====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================
 *  TECHNIQUE 1: XOR CIPHER
 *
 *  How it works:
 *    - Each character of the message is XOR'd with the key character
 *    - XOR is reversible: (A XOR B) XOR B = A
 *    - So the SAME function is used for both hiding and revealing
 *
 *  Example:
 *    'H' XOR 'K' = some scrambled byte
 *    scrambled byte XOR 'K' = 'H'  (original recovered)
 * ================================================================ */

/*
 * xorCipher() - hides OR reveals data using XOR with a key
 * input   : original text
 * key     : secret key string
 * output  : result buffer (must be at least strlen(input)+1 bytes)
 */
void xorCipher(const char *input, const char *key, char *output) {
    int inputLen = strlen(input);
    int keyLen   = strlen(key);

    for (int i = 0; i < inputLen; i++) {
        /* XOR each character with the corresponding key character.
         * We use (i % keyLen) so the key repeats if it's shorter than input. */
        output[i] = input[i] ^ key[i % keyLen];
    }
    output[inputLen] = '\0';  /* null-terminate */
}

/* Print bytes as hex (since XOR output may contain non-printable chars) */
void printAsHex(const char *label, const char *data, int len) {
    printf("%-18s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    printf("\n");
}


/* ================================================================
 *  TECHNIQUE 2: CREDIT CARD MASKING
 *
 *  How it works:
 *    - Keep only the last 4 digits visible
 *    - Replace all other digit characters with '*'
 *    - Non-digit characters (spaces, dashes) are kept as-is
 *
 *  Example:
 *    "4111 1111 1111 1234"  ->  "**** **** **** 1234"
 * ================================================================ */

/*
 * maskCreditCard() - masks a credit card number
 * card    : original card number string (e.g. "4111 1111 1111 1234")
 * masked  : output buffer (same size as card)
 */
void maskCreditCard(const char *card, char *masked) {
    int len = strlen(card);

    /* Count how many digit characters are in the string */
    int digitCount = 0;
    for (int i = 0; i < len; i++) {
        if (card[i] >= '0' && card[i] <= '9') digitCount++;
    }

    /* We want to keep only the LAST 4 digits visible */
    int digitsToHide = digitCount - 4;
    int digitsSeen   = 0;

    for (int i = 0; i < len; i++) {
        if (card[i] >= '0' && card[i] <= '9') {
            digitsSeen++;
            /* If we haven't hidden enough digits yet, replace with '*' */
            if (digitsSeen <= digitsToHide) {
                masked[i] = '*';
            } else {
                masked[i] = card[i];  /* keep last 4 digits */
            }
        } else {
            masked[i] = card[i];  /* keep separators (spaces, dashes) */
        }
    }
    masked[len] = '\0';
}


/* ================================================================
 *  TECHNIQUE 3: EMAIL MASKING
 *
 *  How it works:
 *    - Keep the first character of the username
 *    - Replace the middle with '***'
 *    - Keep everything from '@' onwards visible
 *
 *  Example:
 *    "alice@gmail.com"  ->  "a***@gmail.com"
 *    "bob@yahoo.com"    ->  "b***@yahoo.com"
 * ================================================================ */

/*
 * maskEmail() - masks an email address
 * email   : original email string
 * masked  : output buffer (must be at least strlen(email)+1 bytes)
 */
void maskEmail(const char *email, char *masked) {
    /* Find the position of '@' */
    const char *atSign = strchr(email, '@');

    if (atSign == NULL) {
        /* Not a valid email — just copy as-is */
        strcpy(masked, email);
        return;
    }

    int atPos = (int)(atSign - email);  /* index of '@' */

    /* Copy first character of username */
    masked[0] = email[0];

    /* Replace characters 1 to (atPos-1) with '***' */
    masked[1] = '*';
    masked[2] = '*';
    masked[3] = '*';

    /* Copy from '@' to end of string */
    int j = 4;
    for (int i = atPos; email[i] != '\0'; i++) {
        masked[j++] = email[i];
    }
    masked[j] = '\0';
}


/* ================================================================
 *  TECHNIQUE 4: SIMPLE TEXT STEGANOGRAPHY
 *
 *  How it works:
 *    - Hide a secret message inside a cover text
 *    - Method: insert the secret message character-by-character
 *      between the words of the cover text, using a special
 *      delimiter character (0x01) that won't appear in normal text
 *    - To reveal: extract every character between delimiters
 *
 *  Example:
 *    Cover:  "Hello World"
 *    Secret: "HI"
 *    Result: "H\x01H\x01e\x01I\x01llo World"
 *             ^delimiter marks a hidden character
 *
 *  Note: In real steganography, the hidden data is more cleverly
 *  embedded (e.g. in pixel LSBs of images). This is a simplified
 *  text-based demonstration of the concept.
 * ================================================================ */

#define STEG_DELIMITER '\x01'   /* hidden marker character */

/*
 * hideInText() - hides a secret message inside a cover text
 * cover   : the visible text that will carry the hidden message
 * secret  : the message to hide
 * output  : result buffer (must be large enough)
 *
 * Strategy: Insert each secret character after the first character
 * of each word in the cover text, marked by STEG_DELIMITER.
 */
void hideInText(const char *cover, const char *secret, char *output) {
    int ci = 0;   /* index into cover  */
    int si = 0;   /* index into secret */
    int oi = 0;   /* index into output */
    int secretLen = strlen(secret);
    int coverLen  = strlen(cover);

    while (ci < coverLen) {
        /* Copy one cover character */
        output[oi++] = cover[ci++];

        /* After every cover character, insert one secret character
         * (if there are still secret characters remaining) */
        if (si < secretLen) {
            output[oi++] = STEG_DELIMITER;   /* mark start of hidden char */
            output[oi++] = secret[si++];     /* insert hidden character    */
        }
    }
    output[oi] = '\0';
}

/*
 * revealFromText() - extracts the hidden message from a stego text
 * stegoText : the output from hideInText()
 * secret    : output buffer for the recovered secret message
 */
void revealFromText(const char *stegoText, char *secret) {
    int si = 0;
    int len = strlen(stegoText);

    for (int i = 0; i < len; i++) {
        /* When we find the delimiter, the NEXT character is hidden data */
        if (stegoText[i] == STEG_DELIMITER && i + 1 < len) {
            secret[si++] = stegoText[i + 1];
            i++;  /* skip the hidden character (already read it) */
        }
        /* Normal cover characters are ignored during extraction */
    }
    secret[si] = '\0';
}


/* ================================================================
 *  MAIN - Run all demonstrations
 * ================================================================ */
int main(void) {
    printf("=====================================================\n");
    printf("    DATA HIDING AND MASKING DEMO (C)               \n");
    printf("=====================================================\n\n");

    /* --------------------------------------------------------
     * DEMO 1: XOR Cipher
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 1: XOR Cipher ---\n");

    const char *message = "Hello, Secret World!";
    const char *key     = "MyKey99";

    int msgLen = strlen(message);
    char hidden[100]   = {0};
    char revealed[100] = {0};

    /* Hide the message */
    xorCipher(message, key, hidden);

    /* Reveal the message (same function, same key) */
    xorCipher(hidden, key, revealed);

    printf("Original Message  : %s\n", message);
    printf("XOR Key           : %s\n", key);
    printAsHex("Hidden (hex)", hidden, msgLen);
    printf("Revealed Message  : %s\n", revealed);
    printf("\n");

    /* --------------------------------------------------------
     * DEMO 2: Credit Card Masking
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 2: Credit Card Masking ---\n");

    const char *cards[] = {
        "4111 1111 1111 1234",
        "5500-0000-0000-0004",
        "340000000000009"
    };
    int numCards = 3;

    for (int i = 0; i < numCards; i++) {
        char maskedCard[50] = {0};
        maskCreditCard(cards[i], maskedCard);
        printf("Original  : %s\n", cards[i]);
        printf("Masked    : %s\n\n", maskedCard);
    }

    /* --------------------------------------------------------
     * DEMO 3: Email Masking
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 3: Email Masking ---\n");

    const char *emails[] = {
        "alice@gmail.com",
        "bob.smith@yahoo.com",
        "charlie@company.org"
    };
    int numEmails = 3;

    for (int i = 0; i < numEmails; i++) {
        char maskedEmail[100] = {0};
        maskEmail(emails[i], maskedEmail);
        printf("Original  : %s\n", emails[i]);
        printf("Masked    : %s\n\n", maskedEmail);
    }

    /* --------------------------------------------------------
     * DEMO 4: Text Steganography
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 4: Text Steganography ---\n");

    const char *coverText  = "The weather is nice today and it is sunny outside";
    const char *secretMsg  = "ATTACK";

    char stegoText[500]    = {0};
    char extractedMsg[100] = {0};

    /* Hide the secret inside the cover text */
    hideInText(coverText, secretMsg, stegoText);

    /* Reveal it back */
    revealFromText(stegoText, extractedMsg);

    printf("Cover Text        : %s\n", coverText);
    printf("Secret Message    : %s\n", secretMsg);
    printf("Stego Text Length : %d bytes (cover + hidden data)\n",
           (int)strlen(stegoText));
    printf("Extracted Secret  : %s\n", extractedMsg);
    printf("\n");
    printf("Note: The stego text looks like normal text when printed,\n");
    printf("but it carries hidden characters between the visible ones.\n");

    printf("\n=====================================================\n");
    printf("All demonstrations complete.\n");
    printf("=====================================================\n");

    return 0;
}
