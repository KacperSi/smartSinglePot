#include <stdio.h>
#include "spiffs_config.h"

void config_spiffs(){
    esp_err_t result = esp_vfs_spiffs_register(&spiffs_config);
    if (result != ESP_OK){
        printf("Failed to initialize SPIFFS (%s)", esp_err_to_name(result));
    }
    else{
        printf("SPIFFS initialized\n");
    }
}