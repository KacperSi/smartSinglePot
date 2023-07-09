#ifndef SERVER_H
#define SERVER_H

#include "esp_log.h"

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
    .user_ctx  = "Hello World!"
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

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */