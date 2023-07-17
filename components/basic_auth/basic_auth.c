#include "basic_auth.h"
#include "esp_log.h"
#include <esp_tls_crypto.h>
#include "flash_operations.h"

static const char *TAG = "basic_auth";

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

char *http_auth_basic(const char *username, const char *password)
{
    int out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    asprintf(&user_info, "%s:%s", username, password);
    if (!user_info) {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
    */
    digest = calloc(1, 6 + n + 1);
    if (digest) {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, (size_t *)&out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

bool basic_authentication(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;

    char *username = read_flash_str("BASIC_CRED", "username");
    char *password = read_flash_str("BASIC_CRED", "password");

    basic_auth_info_t *basic_auth_info = default_pass;

    if(username && password){
        basic_auth_info_t *changed_pass = calloc(1, sizeof(basic_auth_info_t));
        if (changed_pass) {
            changed_pass->username = username;
            changed_pass->password = password;
            basic_auth_info = changed_pass;
        }
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1) {
        buf = calloc(1, buf_len);
        if (!buf) {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return false;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        } else {
            ESP_LOGE(TAG, "No auth value received");
            return false;
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials) {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return false;
        }
        if (strncmp(auth_credentials, buf, buf_len)) {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
            free(auth_credentials);
            free(buf);
            return false;
        } else {
            ESP_LOGI(TAG, "Authenticated!");
            free(auth_credentials);
            free(buf);
            return true;
        }
        
    } else {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
        return false;
    }
    return false;
}

void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *default_basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (default_basic_auth_info) {
        default_basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        default_basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;
        default_pass = default_basic_auth_info;
    }
}
