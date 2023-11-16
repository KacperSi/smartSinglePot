#ifndef SPIFFS_H
#define SPIFFS_H

#include "esp_spiffs.h"

#ifdef __cplusplus
extern "C" {
#endif

void config_spiffs();

esp_vfs_spiffs_conf_t spiffs_config = {
        .base_path = "/files",
        .partition_label = NULL,
        .max_files = 3,
        .format_if_mount_failed = true
    };

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SPIFFS_H */