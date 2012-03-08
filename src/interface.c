/**************************************************************************************/
/* This file implements the deterministic part of the Fortuna cryptographic PRNG      */
/* described in "Practical Crytography" by Ferguson & Schneier used to produce        */
/* an initial state of another large period generator. The user may provide an        */
/* arbitrary length input sequence. If it is longer than 256 bits, it is split into   */
/* blocks of 256 bits, each of which is used as a key in an instance of Fortuna       */
/* generator. The output sequences obtained from the Fortuna generators are combined  */
/* by XOR to a single sequence. The instances of Fortuna use disjoint counter         */
/* sequences so that redundancy in the user input does not imply redundancy in the    */
/* output.                                                                            */
/* The code in this file calls functions from Advanced Encryption Standard            */
/* implementation by Christophe Devine. See "aes.c" for the copyright information.    */
/* Petr Savicky 2012                                                                  */
/**************************************************************************************/

#include "aes.h"
#include <R.h>

static aes_context *ctx;

static unsigned char key[32];
static unsigned char plaintext[16];
static unsigned char cipher[16];

void getVectorSeed(int *n, double *x, int *m, unsigned int *y)
{
    int i, j, k;
    unsigned int u;
    if (ctx == NULL) {
        ctx = Calloc(1, aes_context);
    }
    for (i = 0; i < 16; i++) {
        plaintext[i] = 0;
    }
    j = 0;
    for (i = 0; i < *n; i++) { // *n is a multiple of 8 from R
        u = (unsigned int) x[i];
        key[j++] = (unsigned char) (u >> 24);
        key[j++] = (unsigned char) (u >> 16);
        key[j++] = (unsigned char) (u >>  8);
        key[j++] = (unsigned char) (u);
        if (j == 32) {
            aes_set_key(ctx, key, 256);
            u = (unsigned int) i/8;
            plaintext[0] = (unsigned char) (u >> 24);
            plaintext[1] = (unsigned char) (u >> 16);
            plaintext[2] = (unsigned char) (u >>  8);
            plaintext[3] = (unsigned char) (u);
            for (k = 0; k < *m; ) { // *m is a multiple of 4 from R
                u = (unsigned int) k/4;
                plaintext[4] = (unsigned char) (u >> 24);
                plaintext[5] = (unsigned char) (u >> 16);
                plaintext[6] = (unsigned char) (u >>  8);
                plaintext[7] = (unsigned char) (u);
                aes_encrypt(ctx, plaintext, cipher);
                // y[] is initially all 0s from R
                // combine the bytes of cipher to integers in an endianness independent way
                y[k++] ^= (cipher[ 0] << 24) | (cipher[ 1] << 16) | (cipher[ 2] << 8) | (cipher[ 3]);
                y[k++] ^= (cipher[ 4] << 24) | (cipher[ 5] << 16) | (cipher[ 6] << 8) | (cipher[ 7]);
                y[k++] ^= (cipher[ 8] << 24) | (cipher[ 9] << 16) | (cipher[10] << 8) | (cipher[11]);
                y[k++] ^= (cipher[12] << 24) | (cipher[13] << 16) | (cipher[14] << 8) | (cipher[15]);
            }
            j = 0;
        }
    }
}

