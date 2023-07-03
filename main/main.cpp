#include "esp_wifi.h"
#include "esp_log.h"
#include "access_point.h"
#include "nvsManager.hpp"
#include <esp_http_server.h>
#include "http_server.h"

static const char *TAG = "main";

extern "C" void app_main(void)
{
    static httpd_handle_t server = NULL;

    NVSManager M;
    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &connect_handler, &server));
}
