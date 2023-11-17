#ifndef SERVER_H
#define SERVER_H

#include "esp_log.h"
#include <esp_event.h>
#include <esp_http_server.h>

#define BASIC_AUTH_MODE      true
#define UUID_AUTH_MODE      false

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t hello_get_handler_station(httpd_req_t *req);

static const httpd_uri_t hello = {
    .uri       = "/hello",
    .method    = HTTP_GET,
    .handler   = hello_get_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

esp_err_t moisture_get_handler_station(httpd_req_t *req);

static const httpd_uri_t get_soil_moisture = {
    .uri       = "/get_soil_moisture",
    .method    = HTTP_GET,
    .handler   = moisture_get_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

esp_err_t water_level_handler_station(httpd_req_t *req);

static const httpd_uri_t get_water_level = {
    .uri       = "/get_water_level",
    .method    = HTTP_GET,
    .handler   = water_level_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

esp_err_t get_watering_handler_station(httpd_req_t *req);

static const httpd_uri_t get_watering = {
    .uri       = "/set_watering",
    .method    = HTTP_GET,
    .handler   = get_watering_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

esp_err_t set_watering_handler_station(httpd_req_t *req);

static const httpd_uri_t set_watering = {
    .uri       = "/set_watering",
    .method    = HTTP_POST,
    .handler   = set_watering_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

esp_err_t get_watering_settings_handler_station(httpd_req_t *req);

static const httpd_uri_t get_watering_settings = {
    .uri       = "/set_watering_settings",
    .method    = HTTP_GET,
    .handler   = get_watering_settings_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

esp_err_t set_watering_settings_handler_station(httpd_req_t *req);

static const httpd_uri_t set_watering_settings = {
    .uri       = "/set_watering_settings",
    .method    = HTTP_POST,
    .handler   = set_watering_settings_handler_station,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = NULL
};

/* An HTTP POST handler */
esp_err_t echo_post_handler(httpd_req_t *req);

static const httpd_uri_t echo = {
    .uri       = "/echo",
    .method    = HTTP_POST,
    .handler   = echo_post_handler,
    .user_ctx  = NULL
};

httpd_handle_t start_station_webserver(void);

esp_err_t change_pass_handler(httpd_req_t *req);

static const httpd_uri_t change_pass = {
    .uri       = "/change_pass",
    .method    = HTTP_POST,
    .handler   = change_pass_handler,
};

esp_err_t pub_key_get_p_handler(httpd_req_t *req);

static const httpd_uri_t pub_key_p = {
    .uri       = "/pub_key",
    .method    = HTTP_POST,
    .handler   = pub_key_get_p_handler,
    .user_ctx  = NULL
};

esp_err_t encode_test_p_handler(httpd_req_t *req);

static const httpd_uri_t encode_test_p = {
    .uri       = "/encode_test",
    .method    = HTTP_POST,
    .handler   = encode_test_p_handler,
    .user_ctx  = NULL
};

bool authentication(httpd_req_t *req);
bool watering_time_validation(char *watering_time);

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */