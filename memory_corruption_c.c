#include <stdio.h>

int main(){
    char name[5];

    printf("Enter name: ");
    gets(name);

    printf("Hello %s\n", name);
    return 0;
}