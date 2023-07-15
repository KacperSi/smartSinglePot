
#include <esp_log.h>
#include <sys/param.h>
#include <esp_http_server.h>
#include "http_pot_api.h"
#include "basic_auth.h"


// extern httpd_uri_t echo;

extern esp_err_t basic_auth_middleware_handler(httpd_req_t *req, bool* auth_result);
extern void httpd_register_basic_auth(httpd_handle_t server);

static const char *TAG = "http_pot_api";


///////////////////////////////////////////////////////////////////////////////////

esp_err_t hello_get_handler_station(httpd_req_t *req)
{
    bool auth_result;
    esp_err_t auth_err = basic_auth_middleware_handler(req, &auth_result);
    if(auth_err != ESP_OK){
        return auth_err;
    }
    if(auth_result){

        char*  buf;
        size_t buf_len;

        /* Get header value string length and allocate memory for length + 1,
        * extra byte for null termination */
        buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
        if (buf_len > 1) {
            buf = malloc(buf_len);
            /* Copy null terminated value string into buffer */
            if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
                ESP_LOGI(TAG, "Found header => Host: %s", buf);
            }
            free(buf);
        }

        buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
        if (buf_len > 1) {
            buf = malloc(buf_len);
            if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
                ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
            }
            free(buf);
        }

        buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
        if (buf_len > 1) {
            buf = malloc(buf_len);
            if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
                ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
            }
            free(buf);
        }

        /* Read URL query string length and allocate memory for length + 1,
        * extra byte for null termination */
        buf_len = httpd_req_get_url_query_len(req) + 1;
        if (buf_len > 1) {
            buf = malloc(buf_len);
            if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query => %s", buf);
                char param[32];
                /* Get value of expected key from query string */
                if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
                }
                if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
                }
                if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
                }
            }
            free(buf);
        }

        /* Set some custom headers */
        httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
        httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

        /* Send response with custom headers and body set as the
        * string passed in user context*/
        //const char* resp_str = (const char*) req->user_ctx;
        httpd_resp_send(req, "tera git", HTTPD_RESP_USE_STRLEN);

        /* After sending the HTTP response the old HTTP request
        * headers are lost. Check if HTTP request headers can be read now. */
        if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
            ESP_LOGI(TAG, "Request headers lost");
        }
    }
    return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////////

/* An HTTP POST handler */
esp_err_t echo_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                        MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

httpd_handle_t start_station_webserver(void){
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        //httpd_register_uri_handler(server, &hello);
        httpd_register_uri_handler(server, &echo);
        #if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
        httpd_register_uri_handler(server, &hello);
        #endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}