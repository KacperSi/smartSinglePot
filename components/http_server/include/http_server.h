#ifndef SERVER_H
#define SERVER_H

#include "basic_auth.h"

#define ESP_DEVICE_ID      CONFIG_ESP_DEVICE_ID
#define DEVICE_HOSTNAME_RET      CONFIG_DEVICE_HOSTNAME
#define BASIC_AUTH_MODE_RET      true
#define UUID_AUTH_MODE_RET      false

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t stop_webserver(httpd_handle_t server);

void disconnect_server(httpd_handle_t* server);

void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data);

esp_err_t set_wifi_post_handler(httpd_req_t *req);

static const httpd_uri_t set_wifi = {
    .uri       = "/set_wifi",
    .method    = HTTP_POST,
    .handler   = set_wifi_post_handler,
    .user_ctx  = NULL
};

esp_err_t get_hostname_handler_station(httpd_req_t *req);

static const httpd_uri_t get_hostname = {
    .uri       = "/get_hostname",
    .method    = HTTP_GET,
    .handler   = get_hostname_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

esp_err_t pub_key_get_handler(httpd_req_t *req);

static const httpd_uri_t pub_key = {
    .uri       = "/pub_key",
    .method    = HTTP_POST,
    .handler   = pub_key_get_handler,
    .user_ctx  = NULL
};

esp_err_t encode_test_handler(httpd_req_t *req);

static const httpd_uri_t encode_test = {
    .uri       = "/encode_test",
    .method    = HTTP_POST,
    .handler   = encode_test_handler,
    .user_ctx  = NULL
};

void set_spiffs();
httpd_handle_t start_webserver(void);
bool authentication_2f(httpd_req_t *req);
bool authentication_uuid(httpd_req_t *req);

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */