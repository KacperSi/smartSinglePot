#include "esp_wifi.h"
#include "esp_log.h"
#include "access_point.h"
#include "nvs_config.h"
#include <esp_http_server.h>
#include "wifi_station.h"
#include "http_server.h"
#include "http_pot_api.h"
#include "flash_operations.h"
#include "ble_security_gatts.h"
#include "gpio_config.h"
#include "spiffs_config.h"


bool AP_mode = false; //zmienna symulująca przycisk
extern httpd_handle_t start_station_webserver();
extern void start_security_BLE();
extern void config_spiffs();

static const char *TAG = "main";


void app_main(void)
{
    config_spiffs();
    gpio_init();
    httpd_handle_t server = NULL;
    initialize_nvs_C();
    start_security_BLE();

    char *AP_SSID = read_flash_str("AP_data", "AP_SSID");
    char *AP_PASS = read_flash_str("AP_data", "AP_PASS");

    if((AP_SSID && AP_PASS) && !AP_mode){
        ESP_LOGI(TAG, "Access point credentials exist");
        ESP_LOGI(TAG, "Connecting to access point: %s", AP_SSID);

        //WIFI_SERVER+API
        ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
        wifi_init_sta();
        server = start_station_webserver();
    }
    else{
        //ACCESS_POINT
        ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
        wifi_init_softap();
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,
                                                   IP_EVENT_AP_STAIPASSIGNED,
                                                   &connect_handler,
                                                   &server));
    }
}