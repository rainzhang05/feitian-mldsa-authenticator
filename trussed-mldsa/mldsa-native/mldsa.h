#ifndef MLDSA_NATIVE_H
#define MLDSA_NATIVE_H

#include <stddef.h>

// Each function returns 0 on success.  Sizes follow FIPS 204 Table 2:
// ML‑DSA‑44: pk=1312, sk=2560, sig=2420 bytes
// ML‑DSA‑65: pk=1952, sk=4032, sig=3309 bytes
// ML‑DSA‑87: pk=2592, sk=4896, sig=4627 bytes

int mldsa44_sizes(size_t *pk_len, size_t *sk_len, size_t *sig_len);
int mldsa65_sizes(size_t *pk_len, size_t *sk_len, size_t *sig_len);
int mldsa87_sizes(size_t *pk_len, size_t *sk_len, size_t *sig_len);

int mldsa44_keypair(unsigned char *pk, unsigned char *sk);
int mldsa65_keypair(unsigned char *pk, unsigned char *sk);
int mldsa87_keypair(unsigned char *pk, unsigned char *sk);

int mldsa44_sign(unsigned char *sig, size_t *sig_len,
                 const unsigned char *msg, size_t msg_len,
                 const unsigned char *sk);
int mldsa65_sign(unsigned char *sig, size_t *sig_len,
                 const unsigned char *msg, size_t msg_len,
                 const unsigned char *sk);
int mldsa87_sign(unsigned char *sig, size_t *sig_len,
                 const unsigned char *msg, size_t msg_len,
                 const unsigned char *sk);

#endif // MLDSA_NATIVE_H