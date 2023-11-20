#include "sntp_config.h"
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_sleep.h"


static const char *TAG = "sntp_config";

void get_time(char *time_str, size_t size)
{
    time_t now;
    struct tm timeinfo;
    time(&now);
    setenv("TZ", "UTC-1", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(time_str, size, "%H:%M", &timeinfo);
}

void time_sync_notification_cb(struct timeval *tv)
{
    ESP_LOGI(TAG, "Time has been synchronized");

    // char current_time[6];
    // get_time(current_time, sizeof(current_time));
    // ESP_LOGI(TAG, "Current time is: %s", current_time);
}

void sntp_config()
{
    ESP_LOGI(TAG, "Initializing SNTP");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_set_time_sync_notification_cb(time_sync_notification_cb);
    sntp_set_sync_mode(SNTP_SYNC_MODE_SMOOTH);
    sntp_init();
}