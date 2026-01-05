#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define N 32
char *arr[N];


int readint(const char *prompt) {
    int val;
    printf("%s", prompt);
    scanf("%d", &val);
    while (getchar() != '\n');
    return val;
}

int get_index (const char *prompt) {
    unsigned int idx;
    idx = readint(prompt);
    if (idx >= N) {
        printf("Invalid index\n");
        exit(-1);
    }
    return idx;
}

void add (void) {
    int idx, size;
    char *s;
    idx = get_index("index: ");
    size = readint("size: ") + 1;
    if (size < 1 || size >= 256) {
        printf("Invalid size\n");
        exit(-1);
    }
    s = malloc(size);
    printf("data: ");
    fgets(s, size, stdin);
    s[strcspn(s, "\n")] = 0;
    arr[idx] = s;
}

void drop (void) {
    int idx = get_index("index: ");
    free(arr[idx]);
    arr[idx] = NULL;
}

void show (void) {
    int idx = get_index("index: ");
    if (!arr[idx]) {
        printf("Invalid index\n");
        return;
    }
    printf("%s\n", arr[idx]);
}

void merge (void) {
    char *a, *b;
    int i = get_index("dst: ");
    int j = get_index("src: ");
    if (!arr[i] || !arr[j]) {
        printf("Invalid index\n");
        return;
    }
    a = arr[i];
    b = arr[j];
    a = realloc(a, strlen(a) + strlen(b) + 1);
    strncat(a, b, strlen(b));
    printf("Merged: %s\n", a);
    free(b);
    arr[i] = a;
    arr[j] = NULL;
}

void menu() {
    printf("[1] add\n[2] drop\n[3] show\n[4] merge\n");
}

int main () {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    int choice;
    
    while (1) {
    
        menu();
        choice = readint("> ");
        switch (choice) {
            case 1: {
                add();
                break;
            }
            case 2: {
                drop();
                break;
            }
            case 3: {
                show();
                break;
            }
            case 4: {
                merge();
                break;
            }
            default: {
                printf("Invalid choice\n");
            }
        }
    }
    return 0;
}
