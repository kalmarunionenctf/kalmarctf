#include <stdio.h>
#include <string.h>

int main() {
    char userinput[100];
    printf("Please enter the flag: ");
    gets(userinput);

    if (strcmp(userinput,"babykalmar{string_compare_rev_ayoooooooo}") != 0) {
        printf("That was not the flag. Terminating program.\n");
        return 0;
    }
    printf("Correct!\n");
    return 0;
}