#include <iostream>
using namespace std;

int main(){
    int numbers[3] = {1, 2, 3};
    int index;

    cout << "Enter an index to write to: ";
    cin >> index;
    numbers[index] = 99;

    cout << "Done" << endl;
    return 0;
}