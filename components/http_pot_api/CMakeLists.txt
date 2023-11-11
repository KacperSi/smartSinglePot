idf_component_register(SRCS "http_pot_api.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_http_server basic_auth json nvs_config http_server auth2uuid)
