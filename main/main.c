#include "esp_wifi.h"
#include "esp_log.h"
#include "access_point.h"
#include "nvs_config.h"
#include <esp_http_server.h>
#include "wifi_station.h"
#include "http_server.h"
#include "http_pot_api.h"


extern httpd_handle_t start_station_webserver();

static const char *TAG = "main";


void app_main(void)
{
    static httpd_handle_t server = NULL;
    initialize_nvs_C();
    
    //ACCESS_POINT

    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();

    /////////////////////////////////////////////
    //SERVER
    // ESP_ERROR_CHECK(esp_netif_init());//nie musi być
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &connect_handler, &server));

    /////////////////////////////////////////////
    //WIFI_SERVER+API
    // ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    
    // wifi_init_sta();
    // server = start_station_webserver();

    /////////////////////////////////////////////
}