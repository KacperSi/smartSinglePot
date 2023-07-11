#include "esp_wifi.h"
#include "esp_log.h"
#include "access_point.h"
#include "nvs_config.h"
#include <esp_http_server.h>
#include "wifi_station.h"
#include "http_server.h"
#include "http_pot_api.h"


bool AP_mode = false;
extern httpd_handle_t start_station_webserver();
httpd_handle_t server;

static const char *TAG = "main";


void app_main(void)
{
    

    server = NULL;
    initialize_nvs_C();

    nvs_handle_t my_handle;
    nvs_open("AP_data", NVS_READWRITE, &my_handle);
    size_t ssid_required_size = 0;
    nvs_get_str(my_handle, "AP_SSID", NULL, &ssid_required_size);
    char *AP_SSID = malloc(ssid_required_size);
    nvs_get_str(my_handle, "AP_SSID", AP_SSID, &ssid_required_size);

    size_t pass_required_size = 0;
    nvs_get_str(my_handle, "AP_PASS", NULL, &pass_required_size);
    char *AP_PASS = malloc(pass_required_size);
    nvs_get_str(my_handle, "AP_PASS", AP_PASS, &pass_required_size);
    nvs_close(my_handle);

    if((AP_SSID && AP_PASS) && !AP_mode){
        ESP_LOGI(TAG, "Access point credentials exist");
        ESP_LOGI(TAG, "Connecting to access point: %s", AP_SSID);
        ESP_LOGI(TAG, "Pass: %s", AP_PASS);

        //WIFI_SERVER+API
        ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
        wifi_init_sta();
        server = start_station_webserver();
    }
    else{
        //ACCESS_POINT
        ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
        wifi_init_softap();
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &connect_handler, &server));
    }
}