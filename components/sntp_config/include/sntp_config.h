#ifndef SNTP_CONFIG_H
#define SNTP_CONFIG_H

#include "esp_sntp.h"

#ifdef __cplusplus
extern "C" {
#endif

void sntp_config();
void time_sync_notification_cb(struct timeval *tv);
void get_time(char *time_str, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* SNTP_CONFIG_H */