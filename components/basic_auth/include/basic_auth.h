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

bool basic_authentication(httpd_req_t *req);

void httpd_register_basic_auth(httpd_handle_t server);

basic_auth_info_t *default_pass;

#ifdef __cplusplus
}
#endif

/* header file contents go here */

#endif /* SERVER_H */