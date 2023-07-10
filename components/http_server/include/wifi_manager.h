#ifndef SERVER_H
#define SERVER_H

#include "esp_log.h"
#define ESP_DEVICE_ID      CONFIG_ESP_DEVICE_ID

#ifdef __cplusplus
extern "C" {
#endif

/* An HTTP GET handler */
// esp_err_t hello_get_handler(httpd_req_t *req);

// httpd_uri_t hello = {
//     .uri       = "/hello",
//     .method    = HTTP_GET,
//     .handler   = hello_get_handler,
//     /* Let's pass response string in user
//      * context to demonstrate it's usage */
//     .user_ctx = NULL
// };

// esp_err_t set_wifi_post_handler(httpd_req_t *req);

// httpd_uri_t set_wifi = {
//     .uri       = "/set_wifi",
//     .method    = HTTP_POST,
//     .handler   = set_wifi_post_handler,
//     .user_ctx  = NULL
// };

// static httpd_handle_t start_webserver(void)
// {
//     httpd_handle_t server = NULL;
//     httpd_config_t config = HTTPD_DEFAULT_CONFIG();
//     config.lru_purge_enable = true;

//     // Start the httpd server
//     //ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
//     if (httpd_start(&server, &config) == ESP_OK)
//     {
//         // Set URI handlers
//         //ESP_LOGI(TAG, "Registering URI handlers");
//         httpd_register_uri_handler(server, &hello);
//         httpd_register_uri_handler(server, &set_wifi);
// #if CONFIG_EXAMPLE_BASIC_AUTH
//         httpd_register_basic_auth(server);
// #endif
//         return server;
//     }

//     //ESP_LOGI(TAG, "Error starting server!");
//     return NULL;
// }

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */