#ifndef RSA_OPERATIONS_H
#define RSA_OPERATIONS_H

#include "mbedtls/rsa.h"

#define KEY_SIZE 512
#define EXPONENT 65537

#ifdef __cplusplus
extern "C" {
#endif

// void print_public_key(mbedtls_rsa_context *rsa);
// void print_private_key(mbedtls_rsa_context *rsa);
void *gen_rsa_keys_pair();
void encode_decode_test();
void gen_key();
void encode_rsa_by_pot_key();


#ifdef __cplusplus
}
#endif

#endif /* RSA_OPERATIONS_H */