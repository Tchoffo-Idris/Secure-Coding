#include <iostream>
using namespace std;

void calculateEaster(int year, int &month, int &day) {
    int a = year % 19;
    int b = year / 100;
    int c = year % 100;
    int d = b / 4;
    int e = b % 4;
    int f = (b + 8) / 25;
    int g = (b - f + 1) / 3;
    int h = (19 * a + b - d - g + 15) % 30;
    int i = c / 4;
    int k = c % 4;
    int l = (32 + 2 * e + 2 * i - h - k) % 7;
    int m = (a + 11 * h + 22 * l) / 451;

    month = (h + l - 7 * m + 114) / 31;
    day = ((h + l - 7 * m + 114) % 31) + 1;
}

int main() {
    int year, em, ed;

    cout << "=== Church Notification System ===\n";
    cout << "Enter year: ";
    cin >> year;

    calculateEaster(year, em, ed);

    cout << "\nResurrection Sunday: " << ed << "/" << em << "/" << year << endl;

    int pd = ed + 49;
    int pm = em;

    if (pm == 3 || pm == 5) {
        if (pd > 31) {
            pd -= 31;
            pm++;
        }
    } else if (pm == 4) {
        if (pd > 30) {
            pd -= 30;
            pm++;
        }
    }

    cout << "Pentecost Sunday: " << pd << "/" << pm << "/" << year << endl;

    return 0;
}