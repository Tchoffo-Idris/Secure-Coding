#include <stdio.h>

int main(){
    int numbers[3] = {1, 2, 3};
    int index;

    printf("Enter index an index to write to: ");
    scanf("%d", &index);

    numbers[index] = 99;
    
    printf("Done\n");
    return 0;
}