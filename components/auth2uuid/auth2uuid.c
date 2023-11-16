#include "auth2uuid.h"
#include "esp_log.h"

static const char *TAG = "auth2uuid";

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

void get_suuid_str(char *suuid_str)
{
    snprintf(suuid_str, 9, "%02x%02x%02x%02x",
             sUUIDValue[0], sUUIDValue[1],
             sUUIDValue[2], sUUIDValue[3]);
}

void reset_dUUIDValue() {
    dUUIDValue[0] = 0x00;
    dUUIDValue[1] = 0x00;
    dUUIDValue[2] = 0x00;
    dUUIDValue[3] = 0x00;
}

bool auth2uuid_authentication(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Downloaded dUUIDValue: %02x %02x %02x %02x", dUUIDValue[0], dUUIDValue[1], dUUIDValue[2], dUUIDValue[3]);

    char *buf = NULL;
    size_t buf_len = 0;

    //uint8_t current_dUUIDValue[4] = {0x01, 0x02, 0x03, 0x04};
    char duuid_str[9]; // 4 bajty * 2 znaki każdy + 1 znak null-terminator

    // bajty jako ciąg znaków
    snprintf(duuid_str, sizeof(duuid_str), "%02x%02x%02x%02x", 
             dUUIDValue[0], dUUIDValue[1], 
             dUUIDValue[2], dUUIDValue[3]);

    // Teraz duuid_str zawiera sformatowany ciąg znaków
    // printf("Formatted string: %s\n", duuid_str);

    buf_len = httpd_req_get_hdr_value_len(req, "UUID") + 1;
    if (buf_len > 1) {
        buf = calloc(1, buf_len);
        if (!buf) {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return false;
        }

        if (httpd_req_get_hdr_value_str(req, "UUID", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => UUID: %s", buf);
        } else {
            ESP_LOGE(TAG, "No uuid auth value received");
            return false;
        }

        // ESP_LOGI(TAG, "Current dUUIDValue: %02x %02x %02x %02x", dUUIDValue[0], dUUIDValue[1], dUUIDValue[2], dUUIDValue[3]);
        // ESP_LOGI(TAG, "Received UUID header: %s", buf);

        if (memcmp(duuid_str, buf, buf_len) != 0 || strcmp(duuid_str, "00000000") == 0) {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
            return false;
        } else {
            ESP_LOGI(TAG, "Authenticated by request uuid!");
            reset_dUUIDValue();
            return true;
        }
        
    } else {
        ESP_LOGE(TAG, "No UUID auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
        return false;
    }
    return false;
}
