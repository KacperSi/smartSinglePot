#include <stdio.h>
#include "gpio_config.h"
#include "flash_operations.h"
#include "sntp_config.h"

static const char *TAG = "gpio_config";

static QueueHandle_t gpio_evt_queue = NULL;

static void IRAM_ATTR gpio_input_handler(void* arg)
{
    uint32_t gpio_num = (uint32_t) arg;
    xQueueSendFromISR(gpio_evt_queue, &gpio_num, NULL);
}

int calculate_humidity_percent(int adc_value){
    int humidity_percent = 100 - ((adc_value - HUMIDTY_VOLT_MIN) / HUMIDTY_VOLT_PITCH);
    if(humidity_percent > 100){
        return 100;
    }
    if(humidity_percent < 0){
        return 0;
    }
    return humidity_percent;
}

int get_soil_humidity_value(){
    int adc_value = adc1_get_raw(ADC1_CHANNEL_6);
    int humidity = calculate_humidity_percent(adc_value);
    ESP_LOGI(TAG, "humidity: %d", humidity);
    return humidity;
}

static void watering_button_handler(int state){
    if(state){
        gpio_set_level(PUMP_PIN, 0);
        ESP_LOGI(TAG, "gpio_set_level(PUMP_PIN, 0);");
    }
    else{
        gpio_set_level(PUMP_PIN, 1);
        ESP_LOGI(TAG, "gpio_set_level(PUMP_PIN, 1);");
    }
}

static void water_level_handler(int state){
    water_level_state = state;
    if(state){
        gpio_set_level(INFO_LED, 0);
    }
    else{
        gpio_set_level(INFO_LED, 1);
    }
}

static void AP_activate(){
    ESP_LOGI(TAG, "Access Point mode activation");
    save_flash_bool("modes", "ap_mode", true);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
}

static void AP_deactivate(){
    ESP_LOGI(TAG, "Access Point mode deactivation");
    save_flash_bool("modes", "ap_mode", false);
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();
}

static void test(){
    xTaskCreate(bt_pairing_handle, "bt_pairing_handle", 2048, NULL, 10, NULL);
}

static void gpio_task(void* arg)
{
    uint32_t io_num;
    for(;;) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            // ESP_LOGI(TAG, "GPIO[%"PRIu32"] intr, val: %d", io_num, gpio_get_level(io_num));
            // if(io_num == WATERING_BUTTON){
            //     watering_button_handler(gpio_get_level(io_num));
            // }
            if(io_num == WATER_LEVEL_SENSOR){
                water_level_handler(gpio_get_level(io_num));
            }
            // if(io_num == AP_BUTTON){
            //     AP_activate();
            // }
            // if(io_num == BLE_BUTTON){
            //     test();
            // }
        }
    }
}

static void ap_mode_handle(void* arg)
{
    TickType_t startTime = xTaskGetTickCount();
    while ((xTaskGetTickCount() - startTime) < pdMS_TO_TICKS(30000)) {
        gpio_set_level(INFO_LED, 1);
        vTaskDelay(pdMS_TO_TICKS(500));
        gpio_set_level(INFO_LED, 0);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    AP_deactivate();
}


void gpio_init(){
    AP_mode_gpio = read_flash_bool("modes", "ap_mode");
    if(AP_mode_gpio){
        xTaskCreate(ap_mode_handle, "ap_mode_handle", 2048, NULL, 10, NULL);
        ESP_LOGI(TAG, "Access Point mode");
    }
    else{
        ESP_LOGI(TAG, "WiFi mode");
    }
    gpio_set_direction(PUMP_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(WATER_LEVEL_SENSOR, GPIO_MODE_INPUT);
    gpio_set_direction(INFO_LED, GPIO_MODE_OUTPUT);
    gpio_set_direction(WATERING_BUTTON, GPIO_MODE_INPUT);
    gpio_pullup_en(WATERING_BUTTON);
    gpio_set_direction(AP_BUTTON, GPIO_MODE_INPUT);
    gpio_pullup_en(AP_BUTTON);
    gpio_set_direction(BLE_BUTTON, GPIO_MODE_INPUT);
    gpio_pullup_en(BLE_BUTTON);

    int level = gpio_get_level(WATER_LEVEL_SENSOR);
    if (level)
    {
        gpio_set_level(INFO_LED, 0);
    }
    else
    {
        gpio_set_level(INFO_LED, 1);
    }
        
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << WATER_LEVEL_SENSOR),
        .mode = GPIO_MODE_INPUT,
        .intr_type = GPIO_INTR_POSEDGE,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
    };

    gpio_config(&io_conf);
    gpio_evt_queue = xQueueCreate(10, sizeof(uint32_t));
    xTaskCreate(gpio_task, "gpio_task", 2048, NULL, 10, NULL);
    // Instalacja obsługi przerwań
    gpio_install_isr_service(0);
    gpio_isr_handler_add(WATERING_BUTTON, gpio_input_handler, (void*) WATERING_BUTTON);
    gpio_isr_handler_add(WATER_LEVEL_SENSOR, gpio_input_handler, (void*) WATER_LEVEL_SENSOR);
    gpio_isr_handler_add(AP_BUTTON, gpio_input_handler, (void*) AP_BUTTON);
    gpio_isr_handler_add(BLE_BUTTON, gpio_input_handler, (void*) BLE_BUTTON);

    adc1_config_width(ADC_WIDTH_BIT_DEFAULT);
    adc1_config_channel_atten(ADC1_CHANNEL_6, ADC_ATTEN_DB_11);
}

static void watering_time_countdown(void* arg)
{
    int watering_max_time = read_flash_int("wat_settings", "wat_max_time");
    vTaskDelay(pdMS_TO_TICKS(watering_max_time * 1000));
    watering_max_time_passed = true;
    gpio_set_level(PUMP_PIN, 0);
    // ESP_LOGI(TAG, "PUMP STOP!");
    vTaskDelete(NULL);
}

void watering_timer_callback(TimerHandle_t xTimer)
{
    ESP_LOGI(TAG, "Watering timer callback");
    char *watering_time = read_flash_str("wat_settings", "wat_time");
    ESP_LOGI(TAG, "Watering time: %s", watering_time);
    char current_time[6];
    get_time(current_time, sizeof(current_time));
    ESP_LOGI(TAG, "Current time is: %s", current_time);
    bool time_correct = (strcmp(current_time, watering_time) == 0);
    if (time_correct)
    {
        ESP_LOGI(TAG, "Watering Time!");
        int moisture_max = read_flash_int("wat_settings", "moisture_max");
        int moisture_min = read_flash_int("wat_settings", "moisture_min");
        ESP_LOGI(TAG, "Moisture max: %d", moisture_max);
        ESP_LOGI(TAG, "Moisture min: %d", moisture_min);
        int current_moisture = get_soil_humidity_value();
        ESP_LOGI(TAG, "Current moisture: %d", current_moisture);
        bool moisture_need_watering = ((current_moisture < moisture_min) && (!(current_moisture > moisture_max)));
        watering_max_time_passed = false;
        bool watering_needed = (moisture_need_watering && !watering_max_time_passed);
        if(watering_needed){
            gpio_set_level(PUMP_PIN, 1);
            xTaskCreate(watering_time_countdown, "watering_time_countdown", 2048, NULL, 10, NULL);
        }
        while (watering_needed)
        {
            vTaskDelay(pdMS_TO_TICKS(500));
            current_moisture = get_soil_humidity_value();
            moisture_need_watering = ((current_moisture < moisture_min) && (!(current_moisture > moisture_max)));
            watering_needed = (moisture_need_watering && !watering_max_time_passed);
        }
        // ESP_LOGI(TAG, "PUMP STOP!");
        gpio_set_level(PUMP_PIN, 0);
    }
}

void watering_config(){
    TimerHandle_t main_timer = xTimerCreate("main_timer", pdMS_TO_TICKS(60000), pdTRUE, (void *)0, watering_timer_callback);

    if (main_timer == NULL) {
        ESP_LOGI(TAG, "Timer not created - error");
    } else {
        if (xTimerStart(main_timer, 0) != pdPASS) {
            ESP_LOGI(TAG, "Timer start error");
        }
        else{
            ESP_LOGI(TAG, "Watering timer started");
        }
    }
}

static void bt_pairing_handle(void* arg)
{
    // ESP_LOGI(TAG, "Bluetooth pairing activated");
    TickType_t startTime = xTaskGetTickCount();
    while ((xTaskGetTickCount() - startTime) < pdMS_TO_TICKS(30000)) {
        gpio_set_level(INFO_LED, 1);
        vTaskDelay(pdMS_TO_TICKS(500));
        gpio_set_level(INFO_LED, 0);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    // ESP_LOGI(TAG, "Bluetooth pairing deactivated");
    int level = gpio_get_level(WATER_LEVEL_SENSOR);
    if (level)
    {
        gpio_set_level(INFO_LED, 0);
    }
    else
    {
        gpio_set_level(INFO_LED, 1);
    }
    vTaskDelete(NULL);
}

void gpio_loop(){
    int watering_button_state = 1;
    int last_wat_butt_state = 1;
    int AP_button_state = 1;
    int BLE_button_state = 1;
    while(1){
        watering_button_state = gpio_get_level(WATERING_BUTTON);
        AP_button_state = gpio_get_level(AP_BUTTON);
        BLE_button_state = gpio_get_level(BLE_BUTTON);
        if(watering_button_state != last_wat_butt_state){
            watering_button_handler(watering_button_state);
            last_wat_butt_state = watering_button_state;
        }
        if(!AP_button_state){
            AP_activate();
        }
        if(!BLE_button_state){
            test();
        }
        
        vTaskDelay(pdMS_TO_TICKS(150));
    }
}