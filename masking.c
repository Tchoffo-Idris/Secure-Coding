/*
 * =====================================================================
 *  DATA MASKING - Demo in C
 *  No external libraries needed. Pure C implementation.
 *
 *  Compile:  gcc masking.c -o masking
 *  Run:      ./masking
 * =====================================================================
 *
 *  WHAT IS DATA MASKING?
 *  ---------------------
 *  Data masking (also called data obfuscation) replaces real sensitive
 *  data with fake but realistic-looking data. The goal is to protect
 *  private information while keeping the data usable (same format,
 *  same length, same structure).
 *
 *  Used in:
 *    - Testing databases (use masked data, not real customer data)
 *    - Logs and reports (show data without exposing sensitive parts)
 *    - Displaying data on screens (e.g. bank app showing card number)
 *
 *  This file demonstrates FIVE masking techniques:
 *    1. Character Substitution  - replace chars with '*' or 'X'
 *    2. Phone Number Masking    - hide middle digits
 *    3. Name Masking            - hide last name
 *    4. Password Masking        - always show fixed number of '*'
 *    5. National ID Masking     - show only last portion
 * =====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================
 *  TECHNIQUE 1: CHARACTER SUBSTITUTION MASKING
 *
 *  How it works:
 *    - Replace characters in a specified range with a mask character
 *    - You choose: start position, end position, mask character
 *
 *  Example:
 *    maskRange("SensitiveData", 3, 10, '*') -> "Sen*******ta"
 * ================================================================ */

/*
 * maskRange() - replaces characters between start and end with maskChar
 * input    : original string
 * output   : result buffer
 * start    : index of first character to mask (0-based)
 * end      : index of last character to mask (inclusive)
 * maskChar : the character used as the mask (e.g. '*' or 'X')
 */
void maskRange(const char *input, char *output, int start, int end, char maskChar) {
    int len = strlen(input);
    for (int i = 0; i < len; i++) {
        if (i >= start && i <= end) {
            output[i] = maskChar;   /* replace with mask character */
        } else {
            output[i] = input[i];   /* keep original character */
        }
    }
    output[len] = '\0';
}


/* ================================================================
 *  TECHNIQUE 2: PHONE NUMBER MASKING
 *
 *  How it works:
 *    - Keep the first 4 digits (country/area code) visible
 *    - Keep the last 3 digits visible
 *    - Hide everything in between with '*'
 *    - Non-digit characters (spaces, dashes) are kept as-is
 *
 *  Example:
 *    "0677-123-456"  ->  "0677-***-456"
 *    "01234 567890"  ->  "0123* ***890"
 * ================================================================ */

/*
 * maskPhone() - masks a phone number
 * phone   : original phone number string
 * masked  : output buffer
 */
void maskPhone(const char *phone, char *masked) {
    int len = strlen(phone);

    /* Count total digits */
    int totalDigits = 0;
    for (int i = 0; i < len; i++) {
        if (phone[i] >= '0' && phone[i] <= '9') totalDigits++;
    }

    /* We show first 4 digits and last 3 digits; hide the middle */
    int showStart = 4;
    int showEnd   = totalDigits - 3;

    int digitsSeen = 0;
    for (int i = 0; i < len; i++) {
        if (phone[i] >= '0' && phone[i] <= '9') {
            digitsSeen++;
            /* Hide the middle digits */
            if (digitsSeen > showStart && digitsSeen <= showEnd) {
                masked[i] = '*';
            } else {
                masked[i] = phone[i];
            }
        } else {
            masked[i] = phone[i];  /* keep separators */
        }
    }
    masked[len] = '\0';
}


/* ================================================================
 *  TECHNIQUE 3: NAME MASKING
 *
 *  How it works:
 *    - Keep the first name fully visible
 *    - Replace the last name with its initial followed by '***'
 *
 *  Example:
 *    "Alice Johnson"  ->  "Alice J***"
 *    "Bob Smith"      ->  "Bob S***"
 * ================================================================ */

/*
 * maskName() - masks a full name (keeps first name, hides last name)
 * fullName : original full name string (e.g. "Alice Johnson")
 * masked   : output buffer
 */
void maskName(const char *fullName, char *masked) {
    /* Find the space that separates first and last name */
    const char *space = strchr(fullName, ' ');

    if (space == NULL) {
        /* Only one name — just copy it as-is */
        strcpy(masked, fullName);
        return;
    }

    int spacePos = (int)(space - fullName);

    /* Copy everything up to and including the space */
    strncpy(masked, fullName, spacePos + 1);

    /* Add the first letter of the last name */
    int j = spacePos + 1;
    masked[j++] = fullName[spacePos + 1];   /* first letter of last name */

    /* Add '***' to hide the rest of the last name */
    masked[j++] = '*';
    masked[j++] = '*';
    masked[j++] = '*';
    masked[j]   = '\0';
}


/* ================================================================
 *  TECHNIQUE 4: PASSWORD MASKING
 *
 *  How it works:
 *    - NEVER reveal the actual password or its length
 *    - Always show exactly 8 '*' characters regardless of length
 *    - This prevents attackers from guessing length from the display
 *
 *  Example:
 *    "abc"             ->  "********"
 *    "myLongPassword"  ->  "********"
 * ================================================================ */

/*
 * maskPassword() - always returns 8 asterisks (hides length too)
 * masked  : output buffer (must be at least 9 bytes)
 */
void maskPassword(char *masked) {
    /* Always show exactly 8 asterisks — never reveal actual length */
    for (int i = 0; i < 8; i++) {
        masked[i] = '*';
    }
    masked[8] = '\0';
}


/* ================================================================
 *  TECHNIQUE 5: NATIONAL ID / SSN MASKING
 *
 *  How it works:
 *    - Hide first portion of the ID number
 *    - Show only the last few characters
 *
 *  Example (US SSN format):
 *    "123-45-6789"  ->  "***-**-6789"
 *
 *  Example (Generic ID):
 *    "AB1234567"    ->  "*****4567"
 * ================================================================ */

/*
 * maskSSN() - masks a US Social Security Number (format: XXX-XX-XXXX)
 * ssn    : original SSN string
 * masked : output buffer
 */
void maskSSN(const char *ssn, char *masked) {
    int len = strlen(ssn);
    for (int i = 0; i < len; i++) {
        /* Keep only the last 4 digits and the separators */
        if (i >= 7) {
            masked[i] = ssn[i];   /* show last 4 digits */
        } else if (ssn[i] == '-') {
            masked[i] = '-';      /* keep separators */
        } else {
            masked[i] = '*';      /* hide digits */
        }
    }
    masked[len] = '\0';
}

/*
 * maskGenericID() - masks a generic ID, showing only last N characters
 * id      : original ID string
 * masked  : output buffer
 * showLast: how many characters to leave visible at the end
 */
void maskGenericID(const char *id, char *masked, int showLast) {
    int len = strlen(id);
    int hideUntil = len - showLast;

    for (int i = 0; i < len; i++) {
        if (i < hideUntil) {
            masked[i] = '*';     /* hide this character */
        } else {
            masked[i] = id[i];  /* show this character */
        }
    }
    masked[len] = '\0';
}


/* ================================================================
 *  MAIN - Run all masking demonstrations
 * ================================================================ */
int main(void) {
    printf("=====================================================\n");
    printf("    DATA MASKING DEMO (C)                          \n");
    printf("=====================================================\n\n");

    char masked[200] = {0};

    /* --------------------------------------------------------
     * DEMO 1: Character Substitution Masking
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 1: Character Substitution ---\n");

    const char *sensitiveData = "SensitiveData123";
    maskRange(sensitiveData, masked, 3, 10, '*');
    printf("Original  : %s\n", sensitiveData);
    printf("Masked    : %s  (positions 3-10 hidden)\n\n", masked);

    const char *accountNum = "ACC-20240001-XYZ";
    maskRange(accountNum, masked, 4, 11, 'X');
    printf("Original  : %s\n", accountNum);
    printf("Masked    : %s  (account number hidden)\n\n", masked);

    /* --------------------------------------------------------
     * DEMO 2: Phone Number Masking
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 2: Phone Number Masking ---\n");

    const char *phones[] = {
        "0677-123-456",
        "01234 567890",
        "+1-800-555-0199"
    };
    int numPhones = 3;

    for (int i = 0; i < numPhones; i++) {
        memset(masked, 0, sizeof(masked));
        maskPhone(phones[i], masked);
        printf("Original  : %-20s   Masked: %s\n", phones[i], masked);
    }
    printf("\n");

    /* --------------------------------------------------------
     * DEMO 3: Name Masking
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 3: Name Masking ---\n");

    const char *names[] = {
        "Alice Johnson",
        "Bob Smith",
        "Charlie Brown"
    };
    int numNames = 3;

    for (int i = 0; i < numNames; i++) {
        memset(masked, 0, sizeof(masked));
        maskName(names[i], masked);
        printf("Original  : %-20s   Masked: %s\n", names[i], masked);
    }
    printf("\n");

    /* --------------------------------------------------------
     * DEMO 4: Password Masking
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 4: Password Masking ---\n");
    printf("(Length is always hidden — always shows 8 stars)\n\n");

    const char *passwords[] = { "abc", "myPassword123", "x" };
    int numPasswords = 3;

    for (int i = 0; i < numPasswords; i++) {
        memset(masked, 0, sizeof(masked));
        maskPassword(masked);
        printf("Original  : %-20s   Masked: %s\n", passwords[i], masked);
    }
    printf("\n");

    /* --------------------------------------------------------
     * DEMO 5: National ID / SSN Masking
     * -------------------------------------------------------- */
    printf("--- TECHNIQUE 5: National ID / SSN Masking ---\n");

    const char *ssn = "123-45-6789";
    memset(masked, 0, sizeof(masked));
    maskSSN(ssn, masked);
    printf("SSN Original  : %s\n", ssn);
    printf("SSN Masked    : %s\n\n", masked);

    const char *ids[] = { "AB1234567", "ID-9876543210", "PASS123456" };
    int numIDs = 3;

    for (int i = 0; i < numIDs; i++) {
        memset(masked, 0, sizeof(masked));
        maskGenericID(ids[i], masked, 4);   /* show last 4 chars */
        printf("Original  : %-20s   Masked: %s\n", ids[i], masked);
    }

    printf("\n=====================================================\n");
    printf("All masking demonstrations complete.\n");
    printf("=====================================================\n");

    return 0;
}
