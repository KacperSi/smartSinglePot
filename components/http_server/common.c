#include <esp_http_server.h>

esp_err_t http_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (err == HTTPD_404_NOT_FOUND)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "{\"message\": \"Not found.\"}");
        return ESP_FAIL;
    }
    else if (err == HTTPD_400_BAD_REQUEST)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "{\"message\": \"Wrong data.\"}");
        return ESP_FAIL;
    }
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "{\"message\": \"Error on server side.\"}");
    return ESP_FAIL;
}