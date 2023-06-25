#include "esp_wifi.h"
#include "esp_log.h"
#include "access_point.h"
#include "nvsManager.hpp"

static const char *TAG = "main";

extern "C" void app_main(void)
{
    NVSManager M;
    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();
}
