#include <stdint.h>
#include <stdio.h>


typedef uint64_t u64;

static u64 dehash (u64 value) {
    for (int i = 0; i < 16; i++) {
        value ^= (value >> 27) ^ (value >> 27*2);
        value ^= (value << 25) ^ (value << 25*2);
        value ^= (value >> 12) ^ (value >> 12*2) ^ (value >> 12*3) ^ (value >> 12*4) ^ (value >> 12*5);
    }
    value = (value >> 20) | (value << 44);
    value ^= 0xaaaaaaaaaaaaaaaa;
    return value;
}

static u64 printval(u64 num) {
    char out[0x10];
    char *ptr = &out[0x10];
    *(--ptr) = 0;
    while (num > 1) {
        *(--ptr) = (num % 26) + 0x61;
        num /= 26;
    }
    printf("%s\n", ptr);
}

u64 nums[] = {
    0x39eda4a27c0507ab,
    0x67228216cde438ef,
    0x49ae4d04a4b5ea08,
    0xa6e3b88d6af92999,
    0x39403f5da078c2a,
    0xefcd7bdd75fb0253,
    0x171880b7af5033ec
};

int main () {
    for (int i = 0; i < sizeof(nums)/sizeof(nums[0]); i++) {
        printval(dehash(nums[i]));
    }
}
