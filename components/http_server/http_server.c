#include <esp_http_server.h>
#include "http_server.h"
#include "esp_log.h"
#include "common.h"

static const char *TAG = "http_server";

extern void httpd_register_basic_auth(httpd_handle_t server);

esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

void disconnect_server(httpd_handle_t* server)
{
    if (*server)
    {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(server) == ESP_OK)
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
    ESP_LOGI(TAG, "connect_handler begin");
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL)
    {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}

httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &set_wifi);
        httpd_register_basic_auth(server);
        httpd_register_uri_handler(server, &hello);
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}