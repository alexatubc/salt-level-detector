/**
 * @file salt-level-detector.c
 * @brief Measures the height of salt in a barrel and reports over e-mail
 * @author alexatubc
 * @date 14-08-2026
 */

#include "driver/mcpwm_cap.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif_types.h"
#include "esp_private/esp_clk.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi_default.h"
#include "esp_wifi_types_generic.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"
#include "freertos/FreeRTOS.h"
#include "freertos/projdefs.h"
#include "freertos/task.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include <mbedtls/base64.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "portmacro.h"
#include "sdkconfig.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

static const char* TAG = "salt_level_detector";
 
#define THRESHOLD_PERCENT           25
#define SENSOR_LOOP_DELAY_MS        1000
#define CHECK_BARREL_DELAY_MIN      60

#define BARREL_HEIGHT_CM            89   
#define ARR_SIZE                    (CHECK_BARREL_DELAY_MIN * 60)
#define ONE_DAY_US (24LL * 60 * 60 * 100000LL)
static int64_t s_last_email_sent_us = 0;

// Pins out from ESP32 Microcontroller
#define JSN_SRO4T_TRIG_GPIO 5
#define JSN_SRO4T_ECHO_GPIO 6

#define MAIL_SERVER         ""
#define MAIL_PORT           ""
#define SENDER_MAIL         ""
#define SENDER_PASSWORD     ""
#define RECIPIENT_MAIL      ""

#define SERVER_USES_STARTSSL 1

#define TASK_STACK_SIZE     (8 * 1024)
#define BUF_SIZE            512

#define VALIDATE_MBEDTLS_RETURN(ret, min_valid_ret, max_valid_ret, goto_label)  \
    do {                                                                        \
        if (ret < min_valid_ret || ret > max_valid_ret) {                       \
            goto goto_label;                                                    \
        }                                                                       \
    } while (0)  

// 
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

// NVS Credentials
#define NVS_NAMEPSACE "wifi_creds"
#define NVS_KEY_SSID "wifi_ssid"
#define NVS_KEY_PASS "wifi_pass"

// Used only if the NVS is empty (e.g. on first use)
#define EXAMPLE_DEFAULT_WIFI_SSID CONFIG_ESP_WIFI_SSID
#define EXAMPLE_DEFAULT_WIFI_PASSWORD CONFIG_ESP_WIFI_PASSWORD

// Used when connection lost/not found
#define EXAMPLE_ESP_MAXIMUM_RETRY CONFIG_ESP_MAXIMUM_RETRY
#define BASE_RETRY_DELAY_MS 1000
#define MAX_RETRY_DELAY_MS 60000
static int s_retry_num = 0;
static uint32_t s_retry_delayms = BASE_RETRY_DELAY_MS;

static EventGroupHandle_t s_wifi_event_group;
EventBits_t bits;

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

/**
 * @brief Handles all Wi-Fi events (scan, connection, disconnection)
 * 
 * @param[in] arg           Arguments for the handler
 * @param[in] event_base    The ID of the base of the event
 * @param[in] event_id      The ID of the event
 * @param[in] event_data    The data specific to the event which needs to be passed in
 *
 * @return None
 */
static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    ESP_LOGD(TAG, "Received Event: Base=%s, ID=%ld", event_base, event_id);

    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "WIFI_EVENT_STA_START: Station mode started.");
                ESP_LOGI(TAG, "Attempting connection...");
                esp_wifi_connect();
                break;

            case WIFI_EVENT_STA_CONNECTED:
                wifi_event_sta_connected_t* connect_event = (wifi_event_sta_connected_t*) event_data;
                ESP_LOGI(TAG, "WIFI_EVENT_STA_CONNECTED: Connected to AP");
                ESP_LOGI(TAG, "  SSID: %.*s, BSSID: " MACSTR ", Channel: %d, AuthMode: %d",
                            connect_event->ssid_len, connect_event->ssid, MAC2STR(connect_event->bssid), 
                            connect_event->channel, connect_event->authmode);
                ESP_LOGI(TAG, "Waiting for IP address via DHCP...");
                s_retry_delayms = BASE_RETRY_DELAY_MS; // Retry delay is reset because there has been a successful connection
                break;

            case WIFI_EVENT_STA_DISCONNECTED:
                wifi_event_sta_disconnected_t* disconnect_event = (wifi_event_sta_disconnected_t*) event_data;
                // Checks if there's been a connection, otherwise ssid_len is NULL
                if (disconnect_event->ssid_len > 0) {
                    ESP_LOGW(TAG, "  SSID: %.*s, BSSID: " MACSTR, disconnect_event->ssid_len,
                                disconnect_event->ssid, MAC2STR(disconnect_event->bssid));
                }

                bool retry = false;
                switch(disconnect_event->reason) {
                    // Retryable reasons
                    case WIFI_REASON_BEACON_TIMEOUT:
                    case WIFI_REASON_AUTH_EXPIRE:
                    case WIFI_REASON_HANDSHAKE_TIMEOUT:
                    case WIFI_REASON_CONNECTION_FAIL:
                    case WIFI_REASON_AP_TSF_RESET:
                    case WIFI_REASON_ROAMING:
                    case WIFI_REASON_ASSOC_TOOMANY:
                        retry = true;
                        break;
                    // Non-retryable reasons
                    case WIFI_REASON_AUTH_FAIL:
                    case WIFI_REASON_ASSOC_FAIL:
                    case WIFI_REASON_NO_AP_FOUND:
                    case WIFI_REASON_MIC_FAILURE:
                    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
                        ESP_LOGE(TAG, "Connection failed due to non-temporary issue . Not retrying automatically.");
                        retry = false;
                        break;
                    default:
                        ESP_LOGW(TAG, "Unhandled disconnect reason: %d. Retrying by default.", disconnect_event->reason);
                        retry = true; // Default to retry for unknown reasons
                        break;
                }

                if (retry && s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
                    ESP_LOGI(TAG, "[Action] Retrying connection (%d/%d) after %" PRIu32 " ms delay...",
                                s_retry_num + 1, EXAMPLE_ESP_MAXIMUM_RETRY, s_retry_delayms);

                    // Warning: Blocks event handler task
                    vTaskDelay(pdMS_TO_TICKS(s_retry_delayms));

                    s_retry_delayms *= 2;
                    if (s_retry_delayms > MAX_RETRY_DELAY_MS) {
                        s_retry_delayms = MAX_RETRY_DELAY_MS;
                    }

                    s_retry_num++;
                    esp_err_t connect_err = esp_wifi_connect();
                    if (connect_err != ESP_OK) {
                            ESP_LOGE(TAG, "esp_wifi_connect failed: %s", esp_err_to_name(connect_err));
                            // Handle connect initiation failure (maybe signal fail bit)
                            if (s_wifi_event_group) {
                                xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                            }
                    } else {
                        ESP_LOGI(TAG, "Connection attempt initiated.");
                    }

                } else if (retry) { // Retries exhausted
                        ESP_LOGE(TAG, "Connection failed after %d retries.", EXAMPLE_ESP_MAXIMUM_RETRY);
                        s_retry_num = 0; 
                        s_retry_delayms = BASE_RETRY_DELAY_MS; 
                        if (s_wifi_event_group) {
                            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                        }
                } else { // Non-retryable error
                        s_retry_num = 0; 
                        s_retry_delayms = BASE_RETRY_DELAY_MS; 
                        if (s_wifi_event_group) {
                            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                        }
                }
                break;

            default:
                ESP_LOGD(TAG, "Unhandled WIFI_EVENT: %ld", event_id);
                break;
        }
    }
    else if (event_base == IP_EVENT) {
        switch(event_id) {
            case IP_EVENT_STA_GOT_IP:
                ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
                ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP: Network Ready!");
                ESP_LOGI(TAG, "  Assigned IP : " IPSTR ", Gateway: " IPSTR ", Netmask: " IPSTR,
                            IP2STR(&event->ip_info.ip), IP2STR(&event->ip_info.gw), IP2STR(&event->ip_info.netmask));

                ESP_LOGI(TAG, "Resetting WiFi retry counter and delay.");
                s_retry_num = 0;
                s_retry_delayms = BASE_RETRY_DELAY_MS;

                if (s_wifi_event_group) {
                    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
                }
                break;

            default:
                ESP_LOGD(TAG, "Unhandled IP_EVENT: %ld", event_id);
                break;
        }
    }
    else {
        ESP_LOGW(TAG, "Received event from unknown base: %s", event_base);
    }
}

/**
 * @brief Initializes the WiFi driver, stores credentials in NVS, and attempts to initiate connection
 */
void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(s_wifi_event_group == NULL ? ESP_FAIL : ESP_OK);

    ESP_LOGI(TAG, "Creating LwIP core task...");
    ESP_ERROR_CHECK(esp_netif_init());

    ESP_LOGI(TAG, "Creating a system event task...");
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_LOGI(TAG, "Creating network interface instance...");
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(sta_netif == NULL ? ESP_FAIL : ESP_OK);

    ESP_LOGI(TAG, "Intializing the WiFi driver...");
    wifi_init_config_t configuration = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&configuration));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    // 
    wifi_config_t wifi_config;
    memset(&wifi_config, 0, sizeof(wifi_config_t));
    bool credentials_found = false;

    // Stores credentials in NVS to allow auto-connection and reconnection
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMEPSACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "NVS handle open successfully.");

        size_t required_size = sizeof(wifi_config.sta.ssid);
        err = nvs_get_str(nvs_handle, NVS_KEY_SSID, (char*)wifi_config.sta.ssid, &required_size);
        if (err == ESP_OK && required_size > 1) { // Checks that SSID isn't empty
            ESP_LOGI(TAG, "Found SSID in NVS: %s", wifi_config.sta.ssid);

            required_size = sizeof(wifi_config.sta.password);
            err = nvs_get_str(nvs_handle, NVS_KEY_PASS, (char*)wifi_config.sta.password, &required_size);
            if (err == ESP_OK && required_size > 1) { // Checks that PASSWORD isn't empty
                ESP_LOGI(TAG, "Found Password in NVS.");
                credentials_found = true;
            } else if (err == ESP_ERR_NVS_NOT_FOUND) {
                ESP_LOGW(TAG, "Password not found in NVS.");
            } else {
                ESP_LOGE(TAG, "Error (%s) reading password from NVS!", esp_err_to_name(err));
            }
        } else if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "SSID not found in NVS.");
        } else {
            ESP_LOGE(TAG, "Error (%s) reading SSID from NVS!", esp_err_to_name(err));
        }

        if (!credentials_found) {
            ESP_LOGW(TAG, "No valid credentials found in NVS. Storing defaults from Kconfig.");
            strncpy((char*)wifi_config.sta.ssid, EXAMPLE_DEFAULT_WIFI_SSID, sizeof(wifi_config.sta.ssid)- 1);
            strncpy((char*)wifi_config.sta.password, EXAMPLE_DEFAULT_WIFI_PASSWORD, sizeof(wifi_config.sta.password)- 1);

            err = nvs_set_str(nvs_handle, NVS_KEY_SSID, (const char*)wifi_config.sta.ssid);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to write SSID to NVS!");
            }
            err = nvs_set_str(nvs_handle, NVS_KEY_PASS, (const char*)wifi_config.sta.password);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to write Password to NVS!");
            }

            err = nvs_commit(nvs_handle);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "NVS commit failed!");
            } else {
                ESP_LOGI(TAG, "Default credentials stored in NVS.");
                credentials_found = true;
            }
        }
        nvs_close(nvs_handle);
    }

    if (!credentials_found) {
        ESP_LOGE(TAG, "Failed to load or store WiFi credentials. Cannot connect.");
        xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        return;
    }

    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_LOGI(TAG, "Configuring WiFi driver as station...");
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    ESP_LOGI(TAG, "Starting the WiFi driver...");
    ESP_ERROR_CHECK(esp_wifi_start());

    bits = xEventGroupWaitBits(s_wifi_event_group,
                               WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE,
                               pdFALSE, portMAX_DELAY);

}
/**
 * @brief 
 *
 * @param[in] cap_chan  what in gods name does this do
 * @param[in] edata     Records time and when events such as rising or falling edge occurs
 * @param[in] user_data 
 *
 * @return
 */
static bool hc_sr04_echo_callback(mcpwm_cap_channel_handle_t cap_chan, const mcpwm_capture_event_data_t *edata, void *user_data)
{
    static uint32_t cap_val_begin_of_sample = 0;
    static uint32_t cap_val_end_of_sample = 0;
    TaskHandle_t task_to_notify = (TaskHandle_t)user_data;
    BaseType_t high_task_wakeup = pdFALSE;

    if (edata->cap_edge == MCPWM_CAP_EDGE_POS) {
        cap_val_begin_of_sample = edata->cap_value;
        cap_val_end_of_sample = cap_val_begin_of_sample;
    } else {
        cap_val_end_of_sample = edata->cap_value;
        uint32_t tof_ticks = cap_val_end_of_sample - cap_val_begin_of_sample;

        // notify the task to calculate the distance
        xTaskNotifyFromISR(task_to_notify, tof_ticks, eSetValueWithOverwrite, &high_task_wakeup);
    }
    return high_task_wakeup == pdTRUE;
}

/**
 * @brief Generates a single pulse on Trig pin to start a new sample
 */
static void gen_trig_output(void)
{
    gpio_set_level(JSN_SRO4T_TRIG_GPIO, 1); // set high
    esp_rom_delay_us(10);
    gpio_set_level(JSN_SRO4T_TRIG_GPIO, 0); // set low
}

/**
 * @brief Initializes and starts capture timer and capture channel, configures pins
 */
static void mcpwm_init(void)
{
    ESP_LOGI(TAG, "Intalling new capture timer...");
    mcpwm_cap_timer_handle_t cap_timer = NULL;
    mcpwm_capture_timer_config_t cap_conf = {
        .clk_src = MCPWM_CAPTURE_CLK_SRC_DEFAULT,
        .group_id = 0,
    };
    ESP_ERROR_CHECK(mcpwm_new_capture_timer(&cap_conf, &cap_timer));

    ESP_LOGI(TAG, "Installing new capture channel...");
    mcpwm_cap_channel_handle_t cap_chan = NULL;
    mcpwm_capture_channel_config_t cap_ch_conf = {
        .gpio_num = JSN_SRO4T_ECHO_GPIO,
        .prescale = 1,
        // capture on both edge
        .flags.neg_edge = true,
        .flags.pos_edge = true,
    };
    ESP_ERROR_CHECK(mcpwm_new_capture_channel(cap_timer, &cap_ch_conf, &cap_chan));
    // pull up the GPIO internally
    ESP_ERROR_CHECK(gpio_set_pull_mode(JSN_SRO4T_ECHO_GPIO, GPIO_PULLUP_ONLY));

    ESP_LOGI(TAG, "Registering capture callback...");
    TaskHandle_t cur_task = xTaskGetCurrentTaskHandle();
    mcpwm_capture_event_callbacks_t cbs = {
        .on_cap = hc_sr04_echo_callback,
    };
    ESP_ERROR_CHECK(mcpwm_capture_channel_register_event_callbacks(cap_chan, &cbs, cur_task));

    ESP_LOGI(TAG, "Enabling capture channel...");
    ESP_ERROR_CHECK(mcpwm_capture_channel_enable(cap_chan));

    ESP_LOGI(TAG, "Configuring Trig pin...");
    gpio_config_t io_conf = {
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = 1ULL << JSN_SRO4T_TRIG_GPIO,
    };
    ESP_ERROR_CHECK(gpio_config(&io_conf));
    // drive low by default
    ESP_ERROR_CHECK(gpio_set_level(JSN_SRO4T_ECHO_GPIO, 0));

    ESP_LOGI(TAG, "Enabling and starting capture timer...");
    ESP_ERROR_CHECK(mcpwm_capture_timer_enable(cap_timer));
    ESP_ERROR_CHECK(mcpwm_capture_timer_start(cap_timer));
}

/**
 * @brief Checks if SMTP server is accessible
 *
 * @param[in] sock_fd   socket
 * @param[in] buf       size of the buffer
 * @param[in] len       maximum length of message 
 *
 * @return The number of bytes written to SMTP server or read from SMTP server
 */
static int write_and_get_response(mbedtls_net_context *sock_fd, unsigned char *buf, size_t len)
{
    int ret;
    const size_t DATA_SIZE = 128;
    unsigned char data[DATA_SIZE];
    char code[4];
    size_t i, idx = 0;

    if (len) {
        ESP_LOGD(TAG, "%s", buf);
    }

    if (len && (ret = mbedtls_net_send(sock_fd, buf, len)) <= 0) {
        ESP_LOGE(TAG, "mbedtls_net_send failed with error -0x%x", -ret);
        return ret;
    }

    do {
        len = DATA_SIZE - 1;
        memset(data, 0, DATA_SIZE);
        ret = mbedtls_net_recv(sock_fd, data, len);

        if (ret <= 0) {
            ESP_LOGE(TAG, "mbedtls_net_recv failed with error -0x%x", -ret);
            goto exit;
        }

        data[len] = '\0';
        printf("\n%s", data);
        len = ret;
        for (i = 0; i < len; i++) {
            if (data[i] != '\n') {
                if (idx < 4) {
                    code[idx++] = data[i];
                }
                continue;
            }

            if (idx == 4 && code[0] >= '0' && code[0] <= '9' && code[3] == ' ') {
                code[3] = '\0';
                ret = atoi(code);
                goto exit;
            }

            idx = 0;
        }
    } while (1);

exit:
    return ret;
}

/**
 * @brief Checks if SMTP server is accessible through SSL
 *
 * @param[in] ssl 
 * @param[in] buf size of the buffer
 * @param[in] len maximum length of the message 
 * 
 * @return The number of bytes written to SMTP server or read from SMTP server
 */
static int write_ssl_and_get_response(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len)
{
    int ret;
    const size_t DATA_SIZE = 128;
    unsigned char data[DATA_SIZE];
    char code[4];
    size_t i, idx = 0;

    if (len) {
        ESP_LOGD(TAG, "%s", buf);
    }

    while (len && (ret = mbedtls_ssl_write(ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_write failed with error -0x%x", -ret);
            goto exit;
        }
    }

    do {
        len = DATA_SIZE - 1;
        memset(data, 0, DATA_SIZE);
        ret = mbedtls_ssl_read(ssl, data, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            ESP_LOGE(TAG, "mbedtls_ssl_read failed with error -0x%x", -ret);
            goto exit;
        }

        ESP_LOGD(TAG, "%s", data);

        len = ret;
        for (i = 0; i < len; i++) {
            if (data[i] != '\n') {
                if (idx < 4) {
                    code[idx++] = data[i];
                }
                continue;
            }

            if (idx == 4 && code[0] >= '0' && code[0] <= '9' && code[3] == ' ') {
                code[3] = '\0';
                ret = atoi(code);
                goto exit;
            }

            idx = 0;
        }
    } while (1);

exit:
    return ret;
}

/**
 * @brief Writes data through SSL
 *
 * @param[in] ssl
 * @param[in] buf size of the buffer
 * @param[in] len maximum length of the message 
 *
 * @return 0 for success, or error code on failure
 */
static int write_ssl_data(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len)
{
    int ret;

    if (len) {
        ESP_LOGD(TAG, "%s", buf);
    }

    while (len && (ret = mbedtls_ssl_write(ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_write failed with error -0x%x", -ret);
            return ret;
        }
    }

    return 0;
}

static int perform_tls_handshake(mbedtls_ssl_context *ssl)
{
    int ret = -1;
    uint32_t flags;
    char *buf = NULL;
    buf = (char *) calloc(1, BUF_SIZE);
    if (buf == NULL) {
        ESP_LOGE(TAG, "calloc failed for size %d", BUF_SIZE);
        goto exit;
    }

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

    fflush(stdout);
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            goto exit;
        }
    }

    ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(ssl)) != 0) {
        /* In real life, we probably want to close connection if ret != 0 */
        ESP_LOGW(TAG, "Failed to verify peer certificate!");
        mbedtls_x509_crt_verify_info(buf, BUF_SIZE, "  ! ", flags);
        ESP_LOGW(TAG, "verification info: %s", buf);
    } else {
        ESP_LOGI(TAG, "Certificate verified.");
    }

    ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(ssl));
    ret = 0; /* No error */

exit:
    if (buf) {
        free(buf);
    }
    return ret;
}

static void smtp_client_task(void *pvParameters)
{
    char *buf = NULL;
    unsigned char base64_buffer[128];
    int ret, len;
    size_t base64_len;

    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    // mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start,
                                 server_root_cert_pem_end - server_root_cert_pem_start);

    if (ret < 0) {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x", -ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    /* Hostname set here should match CN in server certificate */
    if ((ret = mbedtls_ssl_set_hostname(&ssl, MAIL_SERVER)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned -0x%x", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
        goto exit;
    }

    mbedtls_net_init(&server_fd);

    ESP_LOGI(TAG, "Connecting to %s:%s...", MAIL_SERVER, MAIL_PORT);

    if ((ret = mbedtls_net_connect(&server_fd, MAIL_SERVER,
                                   MAIL_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -0x%x", -ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Connected.");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    buf = (char *) calloc(1, BUF_SIZE);
    if (buf == NULL) {
        ESP_LOGE(TAG, "calloc failed for size %d", BUF_SIZE);
        goto exit;
    }
#if SERVER_USES_STARTSSL
    /* Get response */
    ret = write_and_get_response(&server_fd, (unsigned char *) buf, 0);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    ESP_LOGI(TAG, "Writing EHLO to server...");
    len = snprintf((char *) buf, BUF_SIZE, "EHLO %s\r\n", "ESP32");
    ret = write_and_get_response(&server_fd, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    ESP_LOGI(TAG, "Writing STARTTLS to server...");
    len = snprintf((char *) buf, BUF_SIZE, "STARTTLS\r\n");
    ret = write_and_get_response(&server_fd, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    ret = perform_tls_handshake(&ssl);
    if (ret != 0) {
        goto exit;
    }

#else /* SERVER_USES_STARTSSL */
    ret = perform_tls_handshake(&ssl);
    if (ret != 0) {
        goto exit;
    }

    /* Get response */
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, 0);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);
    ESP_LOGI(TAG, "Writing EHLO to server...");

    len = snprintf((char *) buf, BUF_SIZE, "EHLO %s\r\n", "ESP32");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

#endif /* SERVER_USES_STARTSSL */

    /* Authentication */
    ESP_LOGI(TAG, "Authentication...");

    ESP_LOGI(TAG, "Write AUTH LOGIN");
    len = snprintf( (char *) buf, BUF_SIZE, "AUTH LOGIN\r\n" );
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 399, exit);

    ESP_LOGI(TAG, "Write USER NAME");
    ret = mbedtls_base64_encode((unsigned char *) base64_buffer, sizeof(base64_buffer),
                                &base64_len, (unsigned char *) SENDER_MAIL, strlen(SENDER_MAIL));
    if (ret != 0) {
        ESP_LOGE(TAG, "Error in mbedtls encode! ret = -0x%x", -ret);
        goto exit;
    }
    len = snprintf((char *) buf, BUF_SIZE, "%s\r\n", base64_buffer);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 300, 399, exit);

    ESP_LOGI(TAG, "Write PASSWORD");
    ret = mbedtls_base64_encode((unsigned char *) base64_buffer, sizeof(base64_buffer),
                                &base64_len, (unsigned char *) SENDER_PASSWORD, strlen(SENDER_PASSWORD));
    if (ret != 0) {
        ESP_LOGE(TAG, "Error in mbedtls encode! ret = -0x%x", -ret);
        goto exit;
    }
    len = snprintf((char *) buf, BUF_SIZE, "%s\r\n", base64_buffer);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 399, exit);

    /* Compose email */
    ESP_LOGI(TAG, "Write MAIL FROM");
    len = snprintf((char *) buf, BUF_SIZE, "MAIL FROM:<%s>\r\n", SENDER_MAIL);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    ESP_LOGI(TAG, "Write RCPT");
    len = snprintf((char *) buf, BUF_SIZE, "RCPT TO:<%s>\r\n", RECIPIENT_MAIL);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    ESP_LOGI(TAG, "Write DATA");
    len = snprintf((char *) buf, BUF_SIZE, "DATA\r\n");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 300, 399, exit);

    ESP_LOGI(TAG, "Write Content");
    /* We do not take action if message sending is partly failed. */
    len = snprintf((char *) buf, BUF_SIZE,
                   "From: %s\r\nSubject: [NOTICE] REFILL SALT IN BARREL\r\n"
                   "To: %s\r\n"
                   "MIME-Version: 1.0 (mime-construct 1.9)\n",
                   "ESP32 SMTP Client", RECIPIENT_MAIL);

    /**
     * Note: We are not validating return for some ssl_writes.
     * If by chance, it's failed; at worst email will be incomplete!
     */
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);

    /* Multipart boundary */
    len = snprintf((char *) buf, BUF_SIZE,
                   "Content-Type: multipart/mixed;boundary=XYZabcd1234\n"
                   "--XYZabcd1234\n");
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);

    /* Text */
    len = snprintf((char *) buf, BUF_SIZE,
                   "Content-Type: text/plain\n"
                   "This is a simple test mail from the SMTP client example.\r\n"
                   "\r\n"
                   "The salt in the barrel is under the threshold of %i%%. Please refill it.", THRESHOLD_PERCENT);
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);

    len = snprintf((char *) buf, BUF_SIZE, "\n--XYZabcd1234\n");
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);

    len = snprintf((char *) buf, BUF_SIZE, "\r\n.\r\n");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);
    ESP_LOGI(TAG, "Email sent!");

    /* Close connection */
    mbedtls_ssl_close_notify(&ssl);
    ret = 0; /* No errors */

exit:
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);

    if (ret != 0) {
        mbedtls_strerror(ret, buf, 100);
        ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
    }

    putchar('\n'); /* Just a new line */
    if (buf) {
        free(buf);
    }
    vTaskDelete(NULL);
}
/**
 * @brief Takes average of salt level over time, and checks if it's under threshold
 *
 * @param[in] percent_level_arr array containing data points of barrel salt percent
 *
 * @return returns true if the average percent is below the threshold
 */
bool barrel_below_threshold(float percent_level_arr[])
{
    float average_percent;
    float total = 0;
    for (int i = 0; i < ARR_SIZE; i++) {
        total += percent_level_arr[i];
    }
    average_percent = total / ARR_SIZE;

    if (average_percent < THRESHOLD_PERCENT) {
        return true;
    }
    return false;
    
    
}

void app_main(void)
{
    esp_err_t nvs_ret = nvs_flash_init();
    if (nvs_ret == ESP_ERR_NVS_NO_FREE_PAGES || nvs_ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_ret);

    wifi_init_sta();
    mcpwm_init();

    uint32_t tof_ticks;
    float percent_full_arr[ARR_SIZE];
    int idx = 0;
    while (1) {
        // trigger the sensor to start a new sample
        gen_trig_output();
        // wait for echo done signal
        if (xTaskNotifyWait(0x00, ULONG_MAX, &tof_ticks, pdMS_TO_TICKS(SENSOR_LOOP_DELAY_MS)) == pdTRUE) {
            float pulse_width_us = tof_ticks * (1000000.0 / esp_clk_apb_freq());
            if (pulse_width_us > 35000) {
                // out of range
                continue;
            }
            // convert the pulse width into measure distance
            float distance_cm = (float) pulse_width_us / 58;
            float barrel_percent = (BARREL_HEIGHT_CM - distance_cm) / BARREL_HEIGHT_CM * 100;
            ESP_LOGI(TAG, "Measured distance: %.2fcm, Percent height: %.2f%%", distance_cm, barrel_percent);

            percent_full_arr[idx] = barrel_percent;
            idx = (idx + 1) % ARR_SIZE;
            if (idx == 0 && barrel_below_threshold(percent_full_arr)) {
                int64_t now_us = esp_timer_get_time();
                if (s_last_email_sent_us == 0 || (now_us - s_last_email_sent_us) >= ONE_DAY_US) {
                    xTaskCreate(&smtp_client_task, "smtp_client_task", TASK_STACK_SIZE, NULL, 5, NULL);
                    s_last_email_sent_us = now_us;
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

}