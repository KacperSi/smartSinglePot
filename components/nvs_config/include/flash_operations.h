#ifndef FLASH_OPERATIONS_H
#define FLASH_OPERATIONS_H

#include "nvs.h"

#ifdef __cplusplus
extern "C" {
#endif

const char* read_flash_str(const char* storage, const char* key);
void write_flash_str(const char* storage, const char* key, char* value);

#ifdef __cplusplus
}
#endif

#endif /* FLASH_OPERATIONS_H */