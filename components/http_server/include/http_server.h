#ifndef SERVER_H
#define SERVER_H

#include "basic_auth.h"

#define ESP_DEVICE_ID      CONFIG_ESP_DEVICE_ID

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t stop_webserver(httpd_handle_t server);

void disconnect_server(httpd_handle_t* server);

void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data);

esp_err_t hello_get_handler(httpd_req_t *req);

static const httpd_uri_t hello = {
    .uri       = "/hello",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL
};

esp_err_t set_wifi_post_handler(httpd_req_t *req);

static const httpd_uri_t set_wifi = {
    .uri       = "/set_wifi",
    .method    = HTTP_POST,
    .handler   = set_wifi_post_handler,
    .user_ctx  = NULL
};

httpd_handle_t start_webserver(void);

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */