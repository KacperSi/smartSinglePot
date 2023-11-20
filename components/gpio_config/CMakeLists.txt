idf_component_register(SRCS "gpio_config.c"
                    INCLUDE_DIRS "include"
                    REQUIRES driver nvs_config sntp_config)
