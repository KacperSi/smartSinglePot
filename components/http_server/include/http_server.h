#ifndef SERVER_H
#define SERVER_H

#define ESP_DEVICE_ID      CONFIG_ESP_DEVICE_ID

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t http_error_handler(httpd_req_t *req, httpd_err_code_t err);

esp_err_t stop_webserver(httpd_handle_t server);

void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data);

void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data);

#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */