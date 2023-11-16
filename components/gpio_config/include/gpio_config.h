#ifndef GPIO_CONFIG_H
#define GPIO_CONFIG_H

#define PUMP_PIN GPIO_NUM_23
#define WATER_LEVEL_SENSOR GPIO_NUM_13
#define INFO_LED GPIO_NUM_22
#define WATERING_BUTTON GPIO_NUM_25
#define AP_BUTTON GPIO_NUM_26
#define BLE_BUTTON GPIO_NUM_27

#define HUMIDTY_VOLT_MAX 4095
#define HUMIDTY_VOLT_MIN 1495
#define HUMIDTY_VOLT_PITCH 26

#ifdef __cplusplus
extern "C" {
#endif

static int water_level_state;

void gpio_init();
static void gpio_input_handler(void* arg);
int calculate_humidity_percent(int adc_value);
int get_soil_humidity_value();
static void watering_button_handler(int state);
static void water_level_handler(int state);
static void gpio_task(void* arg);

#ifdef __cplusplus
}
#endif


#endif /* GPIO_CONFIG */