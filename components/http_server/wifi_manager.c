#include <sys/param.h>
#include <esp_http_server.h>
#include "http_server.h"
#include "esp_log.h"
#include <cJSON.h>
#include "wifi_manager.h"
#include "esp_system.h"
#include <string.h>
#include "flash_operations.h"

static const char *TAG = "wifi_manager";

extern bool basic_authentication(httpd_req_t *req);

/* An HTTP GET handler */
esp_err_t hello_get_handler(httpd_req_t *req)
{
    if(basic_authentication(req)){
        /* Send response with custom headers and ESP_DEVICE_ID*/
        const char *resp_str = (const char *)ESP_DEVICE_ID;
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

esp_err_t set_wifi_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, actual_length = req->content_len;
    if (actual_length > sizeof(buf))
    {
        http_error_handler(req, HTTPD_400_BAD_REQUEST);
    }
    int recv_data_length = MIN(actual_length, sizeof(buf));
    
    /* Read the data for the request */
    if ((ret = httpd_req_recv(req, buf, recv_data_length)) <= 0)
    { /* 0 return value indicates connection closed */
        if (ret == HTTPD_SOCK_ERR_TIMEOUT)
        {
            /* Retry receiving if timeout occurred */
            httpd_resp_send_408(req);
        }
        /* In case of error, returning ESP_FAIL will
         * ensure that the underlying socket is closed */
        return ESP_FAIL;
    }

    /* Log data received */
    ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
    ESP_LOGI(TAG, "%.*s", ret, buf);
    ESP_LOGI(TAG, "====================================");

    cJSON *json_data = NULL;
    /* Parse JSON data */
    json_data = cJSON_Parse(buf);
    if (json_data == NULL)
    {
        ESP_LOGE(TAG, "Failed to parse JSON data");
        http_error_handler(req, HTTPD_400_BAD_REQUEST);
    }

    /* Retrieve values from JSON */
    cJSON *cred1 = cJSON_GetObjectItemCaseSensitive(json_data, "cred1");
    cJSON *cred2 = cJSON_GetObjectItemCaseSensitive(json_data, "cred2");

    /* Log parsed values */
    char SSID[32] = "";
    char PASS[32] = "";
    if (cJSON_IsString(cred1) && cJSON_IsString(cred2))
    {
        strcpy(SSID, cred1->valuestring);
        strcpy(PASS, cred2->valuestring);
        ESP_LOGI(TAG, "cred1: %s", cred1->valuestring);
        ESP_LOGI(TAG, "cred2: %s", cred2->valuestring);

    }
    else
    {
        ESP_LOGE(TAG, "Failed to retrieve values from JSON");
        http_error_handler(req, HTTPD_400_BAD_REQUEST);
    }

    /* Free allocated JSON object */
    cJSON_Delete(json_data);

    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_send_chunk(req, NULL, 0);


    write_flash_str("AP_data", "AP_SSID", SSID);
    write_flash_str("AP_data", "AP_PASS", PASS);

    esp_restart();
    return ESP_OK;
}

