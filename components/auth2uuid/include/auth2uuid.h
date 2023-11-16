#ifndef SERVER_H
#define SERVER_H

#include <esp_event.h>
#include <esp_http_server.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t dUUIDValue[4] = {0x00, 0x00, 0x00, 0x00};
uint8_t sUUIDValue[4] = {0x00, 0x00, 0x00, 0x00};

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

bool auth2uuid_authentication(httpd_req_t *req);
void httpd_register_auth2uuid(httpd_handle_t server);
void reset_dUUIDValue();
void get_suuid_str(char *suuid_str);

#ifdef __cplusplus
}
#endif

/* header file contents go here */

#endif /* SERVER_H */