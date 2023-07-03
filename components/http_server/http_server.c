#include <esp_http_server.h>
#include "wifi_manager.h"
#include "http_server.h"

esp_err_t http_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (err == HTTPD_404_NOT_FOUND)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "{\"message\": \"Not found.\"}");
        return ESP_FAIL;
    }
    else if (err == HTTPD_400_BAD_REQUEST)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "{\"message\": \"Wrong data.\"}");
        return ESP_FAIL;
    }
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "{\"message\": \"Error on server side.\"}");
    return ESP_FAIL;
}

esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

void disconnect_handler(void *arg, esp_event_base_t event_base,
                        int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server)
    {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK)
        {
            *server = NULL;
        }
        else
        {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

void connect_handler(void *arg, esp_event_base_t event_base,
                     int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL)
    {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}