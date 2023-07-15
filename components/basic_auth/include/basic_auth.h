#ifndef SERVER_H
#define SERVER_H

#include <esp_event.h>
#include <esp_http_server.h>

#ifdef __cplusplus
extern "C" {
#endif



typedef struct {
    char    *username;
    char    *password;
} basic_auth_info_t;

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

char *http_auth_basic(const char *username, const char *password);

esp_err_t basic_auth_get_handler(httpd_req_t *req);


esp_err_t basic_auth_middleware_handler(httpd_req_t *req, bool* auth_result);

httpd_uri_t basic_auth = {
    .uri       = "/basic_auth",
    .method    = HTTP_GET,
    .handler   = basic_auth_get_handler,
};

void httpd_register_basic_auth(httpd_handle_t server);

basic_auth_info_t *pass;





#ifdef __cplusplus
}
#endif


/* header file contents go here */

#endif /* SERVER_H */