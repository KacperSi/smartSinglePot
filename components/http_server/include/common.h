#ifndef SERVER_H
#define SERVER_H

#include "basic_auth.h"

#define ESP_DEVICE_ID      CONFIG_ESP_DEVICE_ID

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t http_error_handler(httpd_req_t *req, httpd_err_code_t err);

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */