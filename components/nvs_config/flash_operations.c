#include "flash_operations.h"
#include <string.h>
#include "esp_log.h"

static const char *TAG = "flash_operations";

// char* read_flash_str(const char* storage, const char* key) {
//     nvs_handle_t my_handle;
//     nvs_open(storage, NVS_READWRITE, &my_handle);
//     size_t required_size = 0;
//     nvs_get_str(my_handle, key, NULL, &required_size);
//     char *wanted_string = malloc(required_size);
//     nvs_get_str(my_handle, key, wanted_string, &required_size);
//     nvs_close(my_handle);
//     return wanted_string;
// }

char *read_flash_str(const char *storage, const char *key) {
    nvs_handle_t my_handle;
    if (nvs_open(storage, NVS_READWRITE, &my_handle) == ESP_OK) {
        size_t required_size = 0;
        esp_err_t err = nvs_get_str(my_handle, key, NULL, &required_size);
        if (err == ESP_OK) {
            char *wanted_string = malloc(required_size);
            if (wanted_string != NULL) {
                err = nvs_get_str(my_handle, key, wanted_string, &required_size);
                if (err == ESP_OK) {
                    nvs_close(my_handle);
                    return wanted_string;
                } else {
                    ESP_LOGE(TAG, "Error reading flash value: %s", esp_err_to_name(err));
                }
                free(wanted_string);  // Zwolnienie pamięci w przypadku błędu.
            } else {
                ESP_LOGE(TAG, "Memory allocation error");
            }
        } else {
            ESP_LOGE(TAG, "Error getting flash value size: %s", esp_err_to_name(err));
        }
        nvs_close(my_handle);
    } else {
        ESP_LOGE(TAG, "Error opening flash storage");
    }

    return NULL;  // Zwróć NULL w przypadku błędu.
}


// void write_flash_str(const char* storage, const char* key, char* value) {
//     nvs_handle_t my_handle;
//     nvs_open(storage, NVS_READWRITE, &my_handle);
//     nvs_set_str(my_handle, key, value);
//     ESP_LOGI(TAG, "Write data to flash memory: %s\n", value);
//     nvs_commit(my_handle);
//     nvs_close(my_handle);
// }

void write_flash_str(const char *storage, const char *key, char *value) {
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open(storage, NVS_READWRITE, &my_handle);
    if (err == ESP_OK) {
        err = nvs_set_str(my_handle, key, value);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Write data to flash memory: %s", value);
            err = nvs_commit(my_handle);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Error committing flash write: %s", esp_err_to_name(err));
            }
        } else {
            ESP_LOGE(TAG, "Error writing flash value: %s", esp_err_to_name(err));
        }
        nvs_close(my_handle);
    } else {
        ESP_LOGE(TAG, "Error opening flash storage: %s", esp_err_to_name(err));
    }
}

void write_flash_int(const char *storage, const char *key, int value) {
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open(storage, NVS_READWRITE, &my_handle);
    
    if (err == ESP_OK) {
        err = nvs_set_i32(my_handle, key, value);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Write data to flash memory: %d", value);
            err = nvs_commit(my_handle);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Error committing flash write: %s", esp_err_to_name(err));
            }
        } else {
            ESP_LOGE(TAG, "Error writing flash value: %s", esp_err_to_name(err));
        }

        nvs_close(my_handle);
    } else {
        ESP_LOGE(TAG, "Error opening flash storage: %s", esp_err_to_name(err));
    }
}

int read_flash_int(const char *storage, const char *key) {
    nvs_handle_t my_handle;
    if (nvs_open(storage, NVS_READWRITE, &my_handle) == ESP_OK) {
        int32_t value = 0;
        
        esp_err_t err = nvs_get_i32(my_handle, key, &value);
        if (err == ESP_OK) {
            nvs_close(my_handle);
            return value;
        } else {
            ESP_LOGE(TAG, "Error reading flash value: %s", esp_err_to_name(err));
        }

        nvs_close(my_handle);
    } else {
        ESP_LOGE(TAG, "Error opening flash storage");
    }

    return 0;  // Zwróć domyślną wartość w przypadku błędu.
}

void save_pot_rsa_key_to_flash(mbedtls_rsa_context *rsa)
{
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open("keys", NVS_READWRITE, &my_handle);

    if (err == ESP_OK)
    {
        err = nvs_set_blob(my_handle, "pot_rsa_key", rsa, sizeof(mbedtls_rsa_context));
        if (err != ESP_OK)
        {
            printf("Error (%s) writing NVS!\n", esp_err_to_name(err));
        }
        err = nvs_commit(my_handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Error committing flash write: %s", esp_err_to_name(err));
        }
        nvs_close(my_handle);
    }
    else
    {
        ESP_LOGE(TAG, "Error opening flash storage: %s", esp_err_to_name(err));
    }
}

void read_pot_rsa_key_from_flash(mbedtls_rsa_context *rsa)
{
    nvs_handle_t my_handle;
    if (nvs_open("keys", NVS_READWRITE, &my_handle) == ESP_OK)
    {
        // Odczytaj klucz RSA z pamięci flash
        size_t size = sizeof(mbedtls_rsa_context);
        esp_err_t err = nvs_get_blob(my_handle, "pot_rsa_key", rsa, 1000);
        if (err != ESP_OK)
        {
            printf("Error (%s) reading NVS!\n", esp_err_to_name(err));
        }
        if (err == ESP_OK)
        {
            printf("Successfully read RSA key from Flash!\n");
        }
        nvs_close(my_handle);
    }
    else
    {
        ESP_LOGE(TAG, "Error opening flash storage");
    }
}
