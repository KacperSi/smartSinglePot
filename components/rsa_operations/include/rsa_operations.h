#ifndef RSA_OPERATIONS_H
#define RSA_OPERATIONS_H

#include "mbedtls/rsa.h"

#define KEY_SIZE 2048
#define EXPONENT 65537

#ifdef __cplusplus
extern "C" {
#endif

char *get_public_key_pem(mbedtls_rsa_context *rsa);
void *gen_rsa_keys_pair();
void gen_key();
void encrypt_rsa_by_pot_key(unsigned char *input, size_t input_length, unsigned char *output, size_t *output_length);
void decrypt_rsa_by_pot_key(unsigned char *input, size_t input_length, unsigned char *output, size_t *output_length);


#ifdef __cplusplus
}
#endif

#endif /* RSA_OPERATIONS_H */