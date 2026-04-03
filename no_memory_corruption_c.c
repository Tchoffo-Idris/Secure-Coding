#include <stdio.h>

int main(){
    char name[5];

    printf("Enter name: ");
    fgets(name, sizeof(name), stdin);

    printf("Hello %s\n", name);
    return 0;
}