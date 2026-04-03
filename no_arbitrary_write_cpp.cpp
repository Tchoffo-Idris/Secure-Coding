#include <iostream>
using namespace std;

int main(){
    int numbers[3] = {1, 2, 3};
    int index;

    cout << "Enter index (0-2): ";
    cin >> index;

    if (index < 0 || index > 2) {
        cout << "Invalid index" << endl;
        return 1;
    }

    numbers[index] = 99;

    cout << "Safe write" << endl;
    return 0;
}