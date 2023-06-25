#include "esp_event.h"

#define ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define ESP_WIFI_CHANNEL   CONFIG_ESP_WIFI_CHANNEL
#define MAX_STA_CONN       CONFIG_ESP_MAX_STA_CONN

#ifdef __cplusplus
extern "C" {
#endif

void wifi_init_softap(void);
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data);

#ifdef __cplusplus
}
#endif