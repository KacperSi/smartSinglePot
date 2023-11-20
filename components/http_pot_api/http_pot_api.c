
#include <esp_log.h>
#include <sys/param.h>
#include <esp_http_server.h>
#include "http_pot_api.h"
#include "basic_auth.h"
#include "auth2uuid.h"
#include <cJSON.h>
#include "flash_operations.h"
#include "common.h"
#include <string.h>
#include <regex.h>
#include "driver/gpio.h"
#include "gpio_config.h"
#include "rsa_operations.h"

extern uint8_t sUUIDValue[4];

extern void get_suuid_str(char *suuid_str);
extern bool basic_authentication(httpd_req_t *req);
extern bool auth2uuid_authentication(httpd_req_t *req);
extern void httpd_register_basic_auth(httpd_handle_t server);

static const char *TAG = "http_pot_api";
extern esp_err_t http_error_handler(httpd_req_t *req, httpd_err_code_t err);

bool authentication(httpd_req_t *req){
    if(BASIC_AUTH_MODE && UUID_AUTH_MODE){
        return auth2uuid_authentication(req) && basic_authentication(req);
    }
    else if(BASIC_AUTH_MODE){
        return basic_authentication(req);
    }
    else if(UUID_AUTH_MODE){
        return auth2uuid_authentication(req);
    }
    return true;
}

esp_err_t moisture_get_handler_station(httpd_req_t *req)
{
    if (authentication(req))
    {
        int soil_moisture = get_soil_humidity_value();
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddNumberToObject(json_resp, "soil_moisture", soil_moisture);
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

esp_err_t water_level_handler_station(httpd_req_t *req)
{
    if (authentication(req))
    {
        int water_level = gpio_get_level(WATER_LEVEL_SENSOR);
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddNumberToObject(json_resp, "water_level", water_level);
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

esp_err_t get_watering_handler_station(httpd_req_t *req)
{
    if (authentication(req))
    {
        char *watering = "OFF";
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddStringToObject(json_resp, "watering", watering);
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

esp_err_t set_watering_handler_station(httpd_req_t *req)
{
    if (authentication(req))
    {
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
        cJSON *watering_json = cJSON_GetObjectItemCaseSensitive(json_data, "watering");

        /* Log parsed values */
        char watering[4] = ""; // zmienna globalna w nagłówku
        if (cJSON_IsString(watering_json))
        {
            strcpy(watering, watering_json->valuestring);
            ESP_LOGI(TAG, "watering: %s", watering_json->valuestring);
            if (strcmp(watering, "ON") == 0)
            {
                // Włącz diodę LED
                ESP_LOGI(TAG, "Watering ON");
                gpio_set_level(PUMP_PIN, 1);
            }
            else if (strcmp(watering, "OFF") == 0)
            {
                // Wyłącz diodę LED
                ESP_LOGI(TAG, "Watering OFF");
                gpio_set_level(PUMP_PIN, 0);
            }
        }
        else
        {
            ESP_LOGE(TAG, "Failed to retrieve values from JSON");
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }

        /* Free allocated JSON object */
        cJSON_Delete(json_data);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_set_status(req, HTTPD_200);
        httpd_resp_send_chunk(req, NULL, 0);
    }
    return ESP_OK;
}


esp_err_t get_watering_settings_handler_station(httpd_req_t *req)
{
    if (authentication(req))
    {
        int moisture_max = read_flash_int("wat_settings", "moisture_max");
        int moisture_min = read_flash_int("wat_settings", "moisture_min");
        char *watering_time = read_flash_str("wat_settings", "wat_time");
        int watering_max_time = read_flash_int("wat_settings", "wat_max_time");
        cJSON *json_resp = cJSON_CreateObject();
        cJSON_AddNumberToObject(json_resp, "moisture_max", moisture_max);
        cJSON_AddNumberToObject(json_resp, "moisture_min", moisture_min);
        cJSON_AddStringToObject(json_resp, "watering_time", watering_time);
        cJSON_AddNumberToObject(json_resp, "watering_max_time", watering_max_time);
        char *resp_str = cJSON_PrintUnformatted(json_resp);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

bool watering_time_validation(char *watering_time)
{
    const char *pattern = "^[0-2]{1}[0-9]{1}:[0-5]{1}[0-9]{1}$";

    regex_t regex;
    int reti = regcomp(&regex, pattern, REG_EXTENDED);

    if (reti)
    {
        ESP_LOGI(TAG, "Cannot compile a regular expression");
        return false;
    }

    reti = regexec(&regex, watering_time, 0, NULL, 0);
    regfree(&regex);

    if (!reti)
    {
        ESP_LOGI(TAG, "Matched expression");
        return true;
    }
    else if (reti == REG_NOMATCH)
    {
        ESP_LOGI(TAG, "Expression not matched.");
        return false;
    }
    else
    {
        char error_message[100];
        regerror(reti, &regex, error_message, sizeof(error_message));
        ESP_LOGI(TAG, "Error when processing a regular expression: %s", error_message);
        return false;
    }
}

esp_err_t set_watering_settings_handler_station(httpd_req_t *req)
{
    if (authentication(req))
    {
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
        cJSON *moisture_max_json = cJSON_GetObjectItemCaseSensitive(json_data, "moisture_max");
        cJSON *moisture_min_json = cJSON_GetObjectItemCaseSensitive(json_data, "moisture_min");
        cJSON *watering_time_json = cJSON_GetObjectItemCaseSensitive(json_data, "watering_time");
        cJSON *watering_max_time_json = cJSON_GetObjectItemCaseSensitive(json_data, "watering_max_time");

        /* Log parsed values */
        bool types_correct = cJSON_IsNumber(moisture_max_json) && cJSON_IsNumber(moisture_min_json) && cJSON_IsString(watering_time_json) && cJSON_IsNumber(watering_max_time_json);
        bool moisture_correct = false;
        bool watering_max_time_correct = false;
        bool watering_time_correct = false;
        if (types_correct)
        {
            ESP_LOGI(TAG, "Types correct");
            int moisture_max = cJSON_GetNumberValue(moisture_max_json);
            int moisture_min = cJSON_GetNumberValue(moisture_min_json);
            int watering_max_time = cJSON_GetNumberValue(watering_max_time_json);
            char *watering_time = cJSON_GetStringValue(watering_time_json);

            moisture_correct = (moisture_max > 0) && (moisture_max <= 100) && (moisture_min >= 0) && (moisture_min < 100) && (moisture_min < moisture_max);
            watering_max_time_correct = (watering_max_time > 0) && (watering_max_time <= 60);
            watering_time_correct = watering_time_validation(watering_time);

            if(!moisture_correct){
                ESP_LOGI(TAG, "moisture validation error");
            }
            if(!watering_max_time_correct){
                ESP_LOGI(TAG, "watering_max_time validation error");
            }
            if(!watering_time_correct){
                ESP_LOGI(TAG, "watering_time_correct validation error");
            }

            if(moisture_correct && watering_max_time_correct && watering_time_correct){
                write_flash_str("wat_settings", "wat_time", watering_time);
                write_flash_int("wat_settings", "moisture_max", moisture_max);
                write_flash_int("wat_settings", "moisture_min", moisture_min);
                write_flash_int("wat_settings", "wat_max_time", watering_max_time);
                ESP_LOGI(TAG, "Settings saved");
            }
        }
        if(!types_correct || !moisture_correct || !watering_max_time_correct || !watering_time_correct)
        {
            ESP_LOGE(TAG, "Wrong data!");
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }

        /* Free allocated JSON object */
        cJSON_Delete(json_data);
        char suuid_str[9];
        get_suuid_str(suuid_str);
        httpd_resp_set_hdr(req, "UUID", suuid_str);
        httpd_resp_set_status(req, HTTPD_200);
        httpd_resp_send_chunk(req, NULL, 0);
    }
    return ESP_OK;
}


///////////////////////////////////////////////////////////////////



httpd_handle_t start_station_webserver(void){
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.stack_size = 10240;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_basic_auth(server);
        httpd_register_uri_handler(server, &change_pass);
        httpd_register_uri_handler(server, &get_soil_moisture);
        // httpd_register_uri_handler(server, &get_water_level);
        // httpd_register_uri_handler(server, &set_watering);
        // httpd_register_uri_handler(server, &get_watering);
        // httpd_register_uri_handler(server, &get_watering_settings);
        // httpd_register_uri_handler(server, &set_watering_settings);
        httpd_register_uri_handler(server, &pub_key_p);
        httpd_register_uri_handler(server, &encode_test_p);
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

///////////////////////////////////////////////////////////////////

// niesprawdzone endpointy

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

// to zapytanie zabezpieczone tylko przy pomocy auth2uuid
esp_err_t pub_key_get_p_handler(httpd_req_t *req)
{
    if (true)//do testów
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
        unsigned char input[12] = "Hello, RSA!";
        size_t input_length = strlen((char *)input);
        unsigned char encode_output[MBEDTLS_MPI_MAX_SIZE];
        size_t output_length;
        encrypt_rsa_by_pot_key(input, input_length, encode_output, &output_length);
        unsigned char decrypted_data[512];
        size_t decrypted_data_length;
        size_t encrypted_data_length;
        decrypt_rsa_by_pot_key(encode_output, &encrypted_data_length, decrypted_data, &decrypted_data_length);


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

int hex_to_bytes(const char *hex_string, unsigned char **bytes, size_t *length) {
    size_t hex_len = strlen(hex_string);
    if (hex_len % 2 != 0) {
        // Nieparzysta liczba cyfr w reprezentacji heksadecymalnej
        return -1;
    }

    *length = hex_len / 2;
    *bytes = (unsigned char *)malloc(*length);
    if (*bytes == NULL) {
        // Błąd alokacji pamięci
        return -2;
    }

    for (size_t i = 0; i < *length; ++i) {
        if (sscanf(hex_string + 2 * i, "%2hhx", (*bytes) + i) != 1) {
            // Błąd konwersji
            free(*bytes);
            return -3;
        }
    }

    return 0;
}

esp_err_t encode_test_p_handler(httpd_req_t *req)
{
    if (true) //authentication
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
        cJSON *material_json = cJSON_GetObjectItemCaseSensitive(json_data, "material");

        unsigned char decrypted_data[512];
        /* Log parsed values */
        if (cJSON_IsString(material_json))
        {
            char *material = cJSON_GetStringValue(material_json);

            unsigned char *binary_data;
            size_t binary_length;
            int result = hex_to_bytes(material, &binary_data, &binary_length);
            if (result == 0)
            {
                size_t decrypted_data_length;
                size_t encrypted_data_length;
                decrypt_rsa_by_pot_key((unsigned char *)binary_data, &encrypted_data_length, decrypted_data, &decrypted_data_length);
                free(binary_data);
            }
            else
            {
                // Obsługa błędu konwersji z heksa na binarne
                fprintf(stderr, "Błąd konwersji: %d\n", result);
            }
            
        }
        else
        {
            ESP_LOGE(TAG, "Failed to retrieve values from JSON");
            http_error_handler(req, HTTPD_400_BAD_REQUEST);
        }

        /* Free allocated JSON object */
        cJSON_Delete(json_data);
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