#ifndef SERVER_H
#define SERVER_H

#include "esp_log.h"
#include <esp_event.h>
#include <esp_http_server.h>

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

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */