idf_component_register(SRCS "http_server.c" "wifi_manager.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_event nvs_flash esp_netif esp_http_server json http_pot_api nvs_flash)
