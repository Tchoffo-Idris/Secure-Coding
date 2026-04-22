/*
 * =====================================================================
 *  DATA MASKING - Demo in C++
 *  No external libraries needed. Pure C++ OOP implementation.
 *
 *  Compile:  g++ masking.cpp -o masking
 *  Run:      ./masking
 * =====================================================================
 *
 *  WHAT IS DATA MASKING?
 *  ---------------------
 *  Data masking replaces real sensitive values with fake but realistic
 *  data that has the same format. Original data is NOT recoverable
 *  from masked data (unlike encryption).
 *
 *  Used for:
 *    - Protecting customer data in test/dev environments
 *    - Displaying data on dashboards and logs safely
 *    - Compliance with GDPR, HIPAA, PCI-DSS regulations
 *
 *  This file demonstrates FIVE masking classes:
 *    1. CardMasker        - masks credit/debit card numbers
 *    2. EmailMasker       - masks email addresses
 *    3. PhoneMasker       - masks phone numbers
 *    4. PersonMasker      - masks personal details (name, password, DOB)
 *    5. DatabaseMasker    - masks a simulated database record
 * =====================================================================
 */

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>

/* ================================================================
 *  CLASS 1: CardMasker
 *
 *  Masks credit/debit card numbers.
 *
 *  Rules:
 *    - Keep last 4 digits visible
 *    - Replace all other digits with '*'
 *    - Keep formatting characters (spaces, dashes) as-is
 *
 *  Example:
 *    "4111 1111 1111 1234"  ->  "**** **** **** 1234"
 * ================================================================ */
class CardMasker {
public:
    /*
     * mask() - masks a card number, keeping only last 4 digits
     * card : original card number string
     */
    static std::string mask(const std::string &card) {
        /* First, count total digits */
        int totalDigits = 0;
        for (char c : card) {
            if (c >= '0' && c <= '9') totalDigits++;
        }

        /* We will hide everything except the last 4 digits */
        int digitsToHide = totalDigits - 4;
        int digitsSeen   = 0;

        std::string result = card;
        for (int i = 0; i < (int)card.length(); i++) {
            if (card[i] >= '0' && card[i] <= '9') {
                digitsSeen++;
                if (digitsSeen <= digitsToHide) {
                    result[i] = '*';    /* hide this digit */
                }
                /* else: keep it (it's one of the last 4) */
            }
            /* non-digits (spaces, dashes): unchanged */
        }
        return result;
    }

    /*
     * maskWithType() - shows card type and last 4 digits
     * card : original card number
     * type : e.g. "Visa", "Mastercard"
     */
    static std::string maskWithType(const std::string &card,
                                    const std::string &type) {
        /* Get last 4 digits */
        std::string lastFour = "";
        for (char c : card) {
            if (c >= '0' && c <= '9') lastFour += c;
        }
        if (lastFour.length() > 4) {
            lastFour = lastFour.substr(lastFour.length() - 4);
        }
        return type + " ending in " + lastFour;
    }
};


/* ================================================================
 *  CLASS 2: EmailMasker
 *
 *  Masks email addresses.
 *
 *  Rules:
 *    - Keep first character of username
 *    - Replace middle of username with '***'
 *    - Keep domain (everything from '@' onwards) visible
 *
 *  Example:
 *    "alice@gmail.com"   ->  "a***@gmail.com"
 *    "bob.smith@co.uk"   ->  "b***@co.uk"
 * ================================================================ */
class EmailMasker {
public:
    /*
     * mask() - masks an email address
     * email : original email string
     */
    static std::string mask(const std::string &email) {
        /* Find the '@' separator */
        size_t atPos = email.find('@');

        if (atPos == std::string::npos) {
            return email;   /* not a valid email — return as-is */
        }

        /* Keep first char of username + "***" + domain */
        std::string masked = "";
        masked += email[0];           /* first letter of username */
        masked += "***";              /* hide the rest of the username */
        masked += email.substr(atPos); /* keep "@domain.com" */

        return masked;
    }

    /*
     * maskDomain() - also partially hides the domain
     * email : original email string
     */
    static std::string maskDomain(const std::string &email) {
        size_t atPos = email.find('@');
        if (atPos == std::string::npos) return email;

        /* Find the dot in the domain */
        size_t dotPos = email.rfind('.');
        if (dotPos == std::string::npos) return mask(email);

        /* Show: first char of username + *** + @ + *** + .extension */
        std::string masked = "";
        masked += email[0];
        masked += "***@***";
        masked += email.substr(dotPos);   /* keep ".com", ".org", etc. */

        return masked;
    }
};


/* ================================================================
 *  CLASS 3: PhoneMasker
 *
 *  Masks phone numbers.
 *
 *  Rules:
 *    - Keep first 4 digits (country/area code)
 *    - Keep last 3 digits
 *    - Replace middle digits with '*'
 *    - Keep formatting characters (spaces, dashes, parentheses)
 *
 *  Example:
 *    "0677-123-456"   ->  "0677-***-456"
 *    "+1 800 555 0199" -> "+1 800 *** 0199"  (shows area code)
 * ================================================================ */
class PhoneMasker {
public:
    /*
     * mask() - masks a phone number
     * phone : original phone number string
     */
    static std::string mask(const std::string &phone) {
        /* Count total digits */
        int totalDigits = 0;
        for (char c : phone) {
            if (c >= '0' && c <= '9') totalDigits++;
        }

        /* Keep first 4 digits and last 3 digits, hide the rest */
        int keepStart = 4;
        int keepEnd   = totalDigits - 3;

        std::string result = phone;
        int digitsSeen = 0;

        for (int i = 0; i < (int)phone.length(); i++) {
            if (phone[i] >= '0' && phone[i] <= '9') {
                digitsSeen++;
                if (digitsSeen > keepStart && digitsSeen <= keepEnd) {
                    result[i] = '*';    /* hide middle digits */
                }
            }
        }
        return result;
    }
};


/* ================================================================
 *  CLASS 4: PersonMasker
 *
 *  Masks personal details: name, date of birth, password.
 *
 *  Name:
 *    "Alice Johnson"  ->  "Alice J***"
 *
 *  Date of birth:
 *    "1990-05-15"     ->  "****-**-15"  (show only day)
 *
 *  Password:
 *    Any password     ->  "********"   (never reveal length)
 * ================================================================ */
class PersonMasker {
public:
    /*
     * maskName() - hides last name (shows initial + ***)
     * fullName : e.g. "Alice Johnson"
     */
    static std::string maskName(const std::string &fullName) {
        size_t spacePos = fullName.find(' ');

        if (spacePos == std::string::npos) {
            return fullName;    /* single name — return as-is */
        }

        /* First name + space + first letter of last name + *** */
        std::string masked = fullName.substr(0, spacePos + 1);  /* "Alice " */
        masked += fullName[spacePos + 1];                         /* "J"     */
        masked += "***";                                          /* "***"   */
        return masked;
    }

    /*
     * maskDOB() - masks date of birth, keeping only the day
     * dob : date string in format "YYYY-MM-DD"
     */
    static std::string maskDOB(const std::string &dob) {
        if (dob.length() < 10) return "**-**-**";

        /* Format: YYYY-MM-DD  ->  ****-**-DD */
        std::string masked = "****-**-";
        masked += dob.substr(8, 2);   /* keep day (last 2 chars) */
        return masked;
    }

    /*
     * maskPassword() - always returns 8 asterisks (never reveals length)
     */
    static std::string maskPassword() {
        return "********";
    }

    /*
     * maskSSN() - masks Social Security / National ID number
     * id : e.g. "123-45-6789"
     */
    static std::string maskSSN(const std::string &id) {
        std::string masked = id;
        int len = id.length();

        /* Show only last 4 characters */
        for (int i = 0; i < len; i++) {
            if (i < len - 4 && id[i] != '-') {
                masked[i] = '*';
            }
        }
        return masked;
    }
};


/* ================================================================
 *  CLASS 5: DatabaseMasker
 *
 *  Simulates masking an entire database record.
 *  Holds a user record and provides a display() method
 *  that prints the record in masked form.
 *
 *  Real-world use:
 *    - When exporting data for testing, mask the real values
 *    - Log files should never contain real PII (personally identifiable info)
 * ================================================================ */
class DatabaseMasker {
public:
    /* A simulated database record */
    struct UserRecord {
        std::string name;
        std::string email;
        std::string phone;
        std::string cardNumber;
        std::string dateOfBirth;
        std::string password;
        std::string ssn;
    };

    /*
     * displayMasked() - prints a record with all sensitive fields masked
     * record : the original user record
     */
    static void displayMasked(const UserRecord &record) {
        std::cout << "  Name       : " << PersonMasker::maskName(record.name)       << "\n"
                  << "  Email      : " << EmailMasker::mask(record.email)            << "\n"
                  << "  Phone      : " << PhoneMasker::mask(record.phone)            << "\n"
                  << "  Card       : " << CardMasker::mask(record.cardNumber)        << "\n"
                  << "  DOB        : " << PersonMasker::maskDOB(record.dateOfBirth)  << "\n"
                  << "  Password   : " << PersonMasker::maskPassword()               << "\n"
                  << "  SSN/ID     : " << PersonMasker::maskSSN(record.ssn)          << "\n";
    }

    /*
     * displayOriginal() - prints the raw original record (no masking)
     * Only use this to COMPARE with masked output in a demo!
     */
    static void displayOriginal(const UserRecord &record) {
        std::cout << "  Name       : " << record.name        << "\n"
                  << "  Email      : " << record.email       << "\n"
                  << "  Phone      : " << record.phone       << "\n"
                  << "  Card       : " << record.cardNumber  << "\n"
                  << "  DOB        : " << record.dateOfBirth << "\n"
                  << "  Password   : " << record.password    << "\n"
                  << "  SSN/ID     : " << record.ssn         << "\n";
    }
};


/* ================================================================
 *  MAIN - Run all masking demonstrations
 * ================================================================ */
int main() {
    std::cout << "=====================================================\n"
              << "    DATA MASKING DEMO (C++)                        \n"
              << "=====================================================\n\n";

    /* --------------------------------------------------------
     * DEMO 1: Credit Card Masking
     * -------------------------------------------------------- */
    std::cout << "--- CLASS 1: Card Masking ---\n";

    std::vector<std::string> cards = {
        "4111 1111 1111 1234",
        "5500-0000-0000-0004",
        "340000000000009"
    };

    for (const std::string &card : cards) {
        std::cout << "Original  : " << std::left << std::setw(22) << card
                  << "  Masked: " << CardMasker::mask(card) << "\n";
    }
    std::cout << "\n";
    std::cout << "With type : " << CardMasker::maskWithType("4111111111111234", "Visa") << "\n\n";

    /* --------------------------------------------------------
     * DEMO 2: Email Masking
     * -------------------------------------------------------- */
    std::cout << "--- CLASS 2: Email Masking ---\n";

    std::vector<std::string> emails = {
        "alice@gmail.com",
        "bob.smith@yahoo.com",
        "charlie@company.org"
    };

    for (const std::string &email : emails) {
        std::cout << "Original  : " << std::left << std::setw(25) << email
                  << "  Masked: " << EmailMasker::mask(email) << "\n";
    }
    std::cout << "\n";
    std::cout << "Domain also masked: "
              << EmailMasker::maskDomain("alice@gmail.com") << "\n\n";

    /* --------------------------------------------------------
     * DEMO 3: Phone Masking
     * -------------------------------------------------------- */
    std::cout << "--- CLASS 3: Phone Masking ---\n";

    std::vector<std::string> phones = {
        "0677-123-456",
        "01234 567890",
        "+1-800-555-0199"
    };

    for (const std::string &phone : phones) {
        std::cout << "Original  : " << std::left << std::setw(20) << phone
                  << "  Masked: " << PhoneMasker::mask(phone) << "\n";
    }
    std::cout << "\n";

    /* --------------------------------------------------------
     * DEMO 4: Personal Data Masking
     * -------------------------------------------------------- */
    std::cout << "--- CLASS 4: Personal Data Masking ---\n";

    std::cout << "Name :\n";
    std::vector<std::string> names = {"Alice Johnson", "Bob Smith", "Charlie Brown"};
    for (const std::string &name : names) {
        std::cout << "  " << std::left << std::setw(20) << name
                  << "  ->  " << PersonMasker::maskName(name) << "\n";
    }

    std::cout << "\nDate of Birth:\n";
    std::vector<std::string> dobs = {"1990-05-15", "1985-12-31", "2000-01-01"};
    for (const std::string &dob : dobs) {
        std::cout << "  " << std::left << std::setw(14) << dob
                  << "  ->  " << PersonMasker::maskDOB(dob) << "\n";
    }

    std::cout << "\nPassword (length always hidden):\n";
    std::vector<std::string> passwords = {"abc", "myPassword123", "x"};
    for (const std::string &pw : passwords) {
        std::cout << "  " << std::left << std::setw(20) << pw
                  << "  ->  " << PersonMasker::maskPassword() << "\n";
    }
    std::cout << "\n";

    /* --------------------------------------------------------
     * DEMO 5: Full Database Record Masking
     * -------------------------------------------------------- */
    std::cout << "--- CLASS 5: Database Record Masking ---\n";

    DatabaseMasker::UserRecord user = {
        "Alice Johnson",
        "alice@gmail.com",
        "0677-123-456",
        "4111 1111 1111 1234",
        "1990-05-15",
        "mySecretPass99",
        "123-45-6789"
    };

    std::cout << "\nORIGINAL record (as stored in database):\n";
    DatabaseMasker::displayOriginal(user);

    std::cout << "\nMASKED record (safe to show in logs/reports):\n";
    DatabaseMasker::displayMasked(user);

    std::cout << "\n=====================================================\n"
              << "All masking demonstrations complete.\n"
              << "=====================================================\n";

    return 0;
}
