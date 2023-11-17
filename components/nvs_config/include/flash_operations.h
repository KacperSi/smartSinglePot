#ifndef FLASH_OPERATIONS_H
#define FLASH_OPERATIONS_H

#include "nvs.h"
#include "mbedtls/rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

char* read_flash_str(const char* storage, const char* key);
void write_flash_str(const char* storage, const char* key, char* value);
void write_flash_int(const char *storage, const char *key, int value);
int read_flash_int(const char *storage, const char *key);
void save_pot_rsa_key_to_flash(mbedtls_rsa_context *rsa);
void read_pot_rsa_key_from_flash(mbedtls_rsa_context *rsa);
bool read_flash_bool(const char *storage, const char *key);
void save_flash_bool(const char *storage, const char *key, bool value);

#ifdef __cplusplus
}
#endif

#endif /* FLASH_OPERATIONS_H */