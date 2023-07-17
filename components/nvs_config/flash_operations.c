#include "flash_operations.h"
#include <string.h>
#include "esp_log.h"

static const char *TAG = "flash_operations";

char* read_flash_str(const char* storage, const char* key) {
    nvs_handle_t my_handle;
    nvs_open(storage, NVS_READWRITE, &my_handle);
    size_t required_size = 0;
    nvs_get_str(my_handle, key, NULL, &required_size);
    char *wanted_string = malloc(required_size);
    nvs_get_str(my_handle, key, wanted_string, &required_size);
    nvs_close(my_handle);
    return wanted_string;
}

void write_flash_str(const char* storage, const char* key, char* value) {
    nvs_handle_t my_handle;
    nvs_open(storage, NVS_READWRITE, &my_handle);
    nvs_set_str(my_handle, key, value);
    ESP_LOGI(TAG, "Write data to flash memory: %s\n", value);
    nvs_commit(my_handle);
    nvs_close(my_handle);
}