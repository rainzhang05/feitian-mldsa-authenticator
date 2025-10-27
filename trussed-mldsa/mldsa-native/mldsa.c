#include "mldsa.h"
#include <stdlib.h>
#include <string.h>

// Return the sizes of the key and signature for each ML‑DSA parameter set.
int mldsa44_sizes(size_t *pk_len, size_t *sk_len, size_t *sig_len) {
    if (!pk_len || !sk_len || !sig_len) return -1;
    *pk_len  = 1312;
    *sk_len  = 2560;
    *sig_len = 2420;
    return 0;
}

int mldsa65_sizes(size_t *pk_len, size_t *sk_len, size_t *sig_len) {
    if (!pk_len || !sk_len || !sig_len) return -1;
    *pk_len  = 1952;
    *sk_len  = 4032;
    *sig_len = 3309;
    return 0;
}

int mldsa87_sizes(size_t *pk_len, size_t *sk_len, size_t *sig_len) {
    if (!pk_len || !sk_len || !sig_len) return -1;
    *pk_len  = 2592;
    *sk_len  = 4896;
    *sig_len = 4627;
    return 0;
}

static void fill_random(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char) (rand() & 0xff);
    }
}

// Generate a keypair: fill the buffers with pseudo‑random bytes.
int mldsa44_keypair(unsigned char *pk, unsigned char *sk) {
    size_t pk_len, sk_len, sig_len;
    if (mldsa44_sizes(&pk_len, &sk_len, &sig_len) != 0) return -1;
    fill_random(pk, pk_len);
    fill_random(sk, sk_len);
    return 0;
}

int mldsa65_keypair(unsigned char *pk, unsigned char *sk) {
    size_t pk_len, sk_len, sig_len;
    if (mldsa65_sizes(&pk_len, &sk_len, &sig_len) != 0) return -1;
    fill_random(pk, pk_len);
    fill_random(sk, sk_len);
    return 0;
}

int mldsa87_keypair(unsigned char *pk, unsigned char *sk) {
    size_t pk_len, sk_len, sig_len;
    if (mldsa87_sizes(&pk_len, &sk_len, &sig_len) != 0) return -1;
    fill_random(pk, pk_len);
    fill_random(sk, sk_len);
    return 0;
}

// Produce a pseudo‑random signature of the appropriate length.  The message and
// secret key are ignored in this stub implementation.
static int sign_stub(size_t sig_max, unsigned char *sig, size_t *sig_len) {
    if (!sig || !sig_len) return -1;
    fill_random(sig, sig_max);
    *sig_len = sig_max;
    return 0;
}

int mldsa44_sign(unsigned char *sig, size_t *sig_len,
                 const unsigned char *msg, size_t msg_len,
                 const unsigned char *sk) {
    (void)msg;
    (void)msg_len;
    (void)sk;
    size_t pk, sk_len, sig_max;
    if (mldsa44_sizes(&pk, &sk_len, &sig_max) != 0) return -1;
    return sign_stub(sig_max, sig, sig_len);
}

int mldsa65_sign(unsigned char *sig, size_t *sig_len,
                 const unsigned char *msg, size_t msg_len,
                 const unsigned char *sk) {
    (void)msg;
    (void)msg_len;
    (void)sk;
    size_t pk, sk_len, sig_max;
    if (mldsa65_sizes(&pk, &sk_len, &sig_max) != 0) return -1;
    return sign_stub(sig_max, sig, sig_len);
}

int mldsa87_sign(unsigned char *sig, size_t *sig_len,
                 const unsigned char *msg, size_t msg_len,
                 const unsigned char *sk) {
    (void)msg;
    (void)msg_len;
    (void)sk;
    size_t pk, sk_len, sig_max;
    if (mldsa87_sizes(&pk, &sk_len, &sig_max) != 0) return -1;
    return sign_stub(sig_max, sig, sig_len);
}