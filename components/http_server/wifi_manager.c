#include <sys/param.h>
#include <esp_http_server.h>
#include "http_server.h"
#include "esp_log.h"
#include <cJSON.h>
#include "wifi_manager.h"
#include "esp_system.h"
#include <string.h>
#include "flash_operations.h"
#include "auth2uuid.h"
#include "freertos/task.h"
#include "rsa_operations.h"
#include "gpio_config.h"

static const char *TAG = "wifi_manager";

extern void get_suuid_str(char *suuid_str);
extern bool auth2uuid_authentication(httpd_req_t *req);
extern bool basic_authentication(httpd_req_t *req);
extern esp_err_t http_error_handler(httpd_req_t *req, httpd_err_code_t err);
extern void AP_deactivate();

bool authentication_2f(httpd_req_t *req){
    if(BASIC_AUTH_MODE_RET && UUID_AUTH_MODE_RET){
        return auth2uuid_authentication(req) && basic_authentication(req);
    }
    else if(BASIC_AUTH_MODE_RET){
        return basic_authentication(req);
    }
    else if(UUID_AUTH_MODE_RET){
        return auth2uuid_authentication(req);
    }
    return true;
}

bool authentication_uuid(httpd_req_t *req){
    if(UUID_AUTH_MODE_RET){
        return auth2uuid_authentication(req);
    }
    return true;
}

esp_err_t set_wifi_post_handler(httpd_req_t *req)
{
    if(authentication_2f(req)){
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
        // ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        // ESP_LOGI(TAG, "%.*s", ret, buf);
        // ESP_LOGI(TAG, "====================================");

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
        char SSID[32] = "";
        char PASS[32] = "";
        if (cJSON_IsString(cred1) && cJSON_IsString(cred2))
        {
            strcpy(SSID, cred1->valuestring);
            strcpy(PASS, cred2->valuestring);
            ESP_LOGI(TAG, "creds saved");
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

        //httpd_resp_send_chunk(req, NULL, 0);


        write_flash_str("AP_data", "AP_SSID", SSID);
        write_flash_str("AP_data", "AP_PASS", PASS);

        httpd_resp_set_status(req, HTTPD_200);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddStringToObject(json_resp, "additional_info", "-");
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
        cJSON_Delete(json_data);
        vTaskDelay(pdMS_TO_TICKS(2000));
        AP_deactivate();
    }
    return ESP_OK;
}

esp_err_t get_hostname_handler_station(httpd_req_t *req)
{
    if (authentication_2f(req))
    {
        char *hostname = DEVICE_HOSTNAME_RET;
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddStringToObject(json_resp, "hostname", hostname);
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

// to zapytanie zabezpieczone tylko przy pomocy auth2uuid
esp_err_t pub_key_get_handler(httpd_req_t *req)
{
    if (authentication_uuid(req))
    {
        char buf[600];
        int ret = 1, actual_length = req->content_len;
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
        cJSON *key_json = cJSON_GetObjectItemCaseSensitive(json_data, "key");

        /* Log parsed values */
        if (cJSON_IsString(key_json))
        {
            char *key = cJSON_GetStringValue(key_json);
            ESP_LOGI(TAG, "client public key: %s", key);
            write_flash_str("enc_data", "s_pub_key", key);
            ESP_LOGI(TAG, "client key saved");
        }
        else
        {
            ESP_LOGE(TAG, "Failed to retrieve values from JSON");
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }

        /* Free allocated JSON object */
        cJSON_Delete(json_data);

        httpd_resp_set_status(req, HTTPD_200);
        ESP_LOGI(TAG, "key genarete here");
        char *pubKeyPem = gen_rsa_keys_pair();
        ESP_LOGI(TAG, "key save here");
        //char *pot_pub_key = "PSXbC+mc0jhFj3kl5c"; //generacja
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddStringToObject(json_resp, "key", pubKeyPem);
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        cJSON_Delete(json_resp);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

esp_err_t encode_test_handler(httpd_req_t *req)
{
    if (true) //authentication
    {
        char buf[20];
        int ret = 1, actual_length = req->content_len;
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
        cJSON *material_json = cJSON_GetObjectItemCaseSensitive(json_data, "material");

        /* Log parsed values */
        if (cJSON_IsString(material_json))
        {
            char *material = cJSON_GetStringValue(material_json);
        }
        else
        {
            ESP_LOGE(TAG, "Failed to retrieve values from JSON");
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }

        /* Free allocated JSON object */
        cJSON_Delete(json_data);

        //encode_decode_test();
        gen_key();
        // encode_rsa_by_pot_key();

        httpd_resp_set_status(req, HTTPD_200);
        char *response = "poki co nic"; //generacja
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddStringToObject(json_resp, "response", response);
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        cJSON_Delete(json_resp);
        // char suuid_str[9];
        // get_suuid_str(suuid_str);
        // httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}