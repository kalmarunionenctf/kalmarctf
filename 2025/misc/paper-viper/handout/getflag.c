#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *flag = fopen("/flag.txt", "r");
    if (!flag) {
        printf("Error: Cannot open flag file\n");
        return 1;
    }

    char c;
    while ((c = fgetc(flag)) != EOF) {
        putchar(c);
    }

    fclose(flag);
    return 0;
}