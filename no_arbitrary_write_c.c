#include <stdio.h>

int main(){
    int numbers[3] = {1, 2, 3};
    int index;

    printf("Enter index (0-2): ");
    scanf("%d", &index);

    if (index < 0 || index > 2) {
        printf("Invalid index\n");
        return 1;
    }

    numbers[index] = 99;

    printf("Safe write\n");
    return 0;
}