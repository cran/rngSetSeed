// Advanced Encryption Standard
#include "aes.h"
#include <R.h>

#define N 624

static aes_context *ctx;

static unsigned char key[32];
static unsigned char plaintext[16];
static unsigned char cipher[16];
static unsigned char hashValue[16];
// The first 32 hexadecimal digits of the fractional part of the base of the natural logarithms.
static unsigned char num_e[16] = {
    0xB7,0xE1,0x51,0x62,0x8A,0xED,0x2A,0x6A,0xBF,0x71,0x58,0x80,0x9C,0xF4,0xF3,0xC7};

void getVectorSeed(int *n, double *x, unsigned int *y)
{
    int i, j, k;
    unsigned int w;
    if (ctx == NULL) {
        ctx = Calloc(1, aes_context);
    }
    memcpy(hashValue, num_e, 16);
    j = 0;
    for (i = 0; i < *n; i++) { // *n is a multiple of 8
        w = (unsigned int) x[i];
        key[j++] = (unsigned char) (w >> 24);
        key[j++] = (unsigned char) (w >> 16);
        key[j++] = (unsigned char) (w >>  8);
        key[j++] = (unsigned char) (w);
        if (j == 32) {
            aes_set_key(ctx, key, 256);
            aes_encrypt(ctx, hashValue, cipher);
            for (k = 0; k < 16; k++) {
                hashValue[k] ^= cipher[k];
            }
            j = 0;
        }
    }
    //printBytes(hashValue, 16);
    aes_set_key(ctx, hashValue, 128);
    for (i = 0; i < 16; i++) {
        plaintext[i] = 0;
    }
    for (i = 0; i < N; i++) {
        plaintext[2] = (unsigned char) (i >> 8);
        plaintext[3] = (unsigned char) i;
        aes_encrypt(ctx, plaintext, cipher);
        // use the first 4 bytes of cipher in an endianness independent way
        y[i] = (cipher[3] << 24) | (cipher[2] << 16) | (cipher[1] << 8) | (cipher[0]);
    }
}

