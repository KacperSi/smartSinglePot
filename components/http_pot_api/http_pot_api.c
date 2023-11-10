
#include <esp_log.h>
#include <sys/param.h>
#include <esp_http_server.h>
#include "http_pot_api.h"
#include "basic_auth.h"
#include <cJSON.h>
#include "flash_operations.h"
#include "common.h"
#include <string.h>

extern bool basic_authentication(httpd_req_t *req);
extern void httpd_register_basic_auth(httpd_handle_t server);

static const char *TAG = "http_pot_api";
extern esp_err_t http_error_handler(httpd_req_t *req, httpd_err_code_t err);

esp_err_t hello_get_handler_station(httpd_req_t *req)
{
    if(basic_authentication(req)){

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

esp_err_t pub_key_get_handler(httpd_req_t *req)
{
    // to zapytanie ma być niezabezpieczone
    char *key = "klucz";
    cJSON *json_resp = cJSON_CreateObject();
    cJSON_AddStringToObject(json_resp, "key", key);
    char *resp_str = cJSON_PrintUnformatted(json_resp);
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* An HTTP POST handler */
esp_err_t echo_post_handler(httpd_req_t *req)
{
    if(basic_authentication(req)){
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
    }
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
        httpd_register_basic_auth(server);
        httpd_register_uri_handler(server, &change_pass);
        httpd_register_uri_handler(server, &hello);
        httpd_register_uri_handler(server, &pub_key);
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

esp_err_t change_pass_handler(httpd_req_t *req)
{
    if(basic_authentication(req)){
        char buf[100];
        int ret, actual_length = req->content_len;
        if (actual_length > sizeof(buf))
        {
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }
        int recv_data_length = MIN(actual_length, sizeof(buf));
        
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf, recv_data_length)) <= 0)
        { /* 0 return value indicates connection closed */
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry receiving if timeout occurred */
                httpd_resp_send_408(req);
            }
            /* In case of error, returning ESP_FAIL will
            * ensure that the underlying socket is closed */
            return ESP_FAIL;
        }

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");

        cJSON *json_data = NULL;
        /* Parse JSON data */
        json_data = cJSON_Parse(buf);
        if (json_data == NULL)
        {
            ESP_LOGE(TAG, "Failed to parse JSON data");
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }

        /* Retrieve values from JSON */
        cJSON *cred1 = cJSON_GetObjectItemCaseSensitive(json_data, "cred1");
        cJSON *cred2 = cJSON_GetObjectItemCaseSensitive(json_data, "cred2");

        /* Log parsed values */
        char USERNAME[32] = "";
        char PASS[32] = "";
        if (cJSON_IsString(cred1) && cJSON_IsString(cred2))
        {
            strcpy(USERNAME, cred1->valuestring);
            strcpy(PASS, cred2->valuestring);
            ESP_LOGI(TAG, "cred1: %s", cred1->valuestring);
            ESP_LOGI(TAG, "cred2: %s", cred2->valuestring);

        }
        else
        {
            ESP_LOGE(TAG, "Failed to retrieve values from JSON");
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }

        /* Free allocated JSON object */
        cJSON_Delete(json_data);

        httpd_resp_set_status(req, HTTPD_200);
        httpd_resp_send_chunk(req, NULL, 0);


        write_flash_str("BASIC_CRED", "username", USERNAME);
        write_flash_str("BASIC_CRED", "password", PASS);
    }
    return ESP_OK;
}

// do screena

// httpd_handle_t start_station_webserver(void){
//     httpd_handle_t server = NULL;
//     httpd_config_t config = HTTPD_DEFAULT_CONFIG();
//     config.lru_purge_enable = true;

//     // Start the httpd server
//     ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
//     if (httpd_start(&server, &config) == ESP_OK) {
//         ESP_LOGI(TAG, "Registering URI handlers");
//         httpd_register_basic_auth(server);
//         httpd_register_uri_handler(server, &set_wifi);
//         httpd_register_uri_handler(server, &get_hostname);
//         httpd_register_uri_handler(server, &pub_key);
//         return server;
//     }

//     ESP_LOGI(TAG, "Error starting server!");
//     return NULL;
// }