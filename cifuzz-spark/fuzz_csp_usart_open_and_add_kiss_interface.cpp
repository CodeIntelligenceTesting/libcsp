#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <cstring>
#include <csp/csp.h>
#include <csp/drivers/usart.h>
#include <csp/drivers/can_socketcan.h>
#include <csp/interfaces/csp_if_zmqhub.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

// Define buffer size if not already defined
#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

#define MY_SERVER_PORT 10

// Define device types
enum DeviceType {
    DEVICE_UNKNOWN,
    DEVICE_CAN,
    DEVICE_KISS,
    DEVICE_ZMQ
};

// Function to add interface, similar to examples/csp_server.c
csp_iface_t * add_interface(DeviceType device_type, const char * device_name) {
    csp_iface_t * default_iface = NULL;

    if (device_type == DEVICE_KISS) {
        csp_usart_conf_t conf = {
            .device = device_name,
            .baudrate = 115200,
            .databits = 8,
            .stopbits = 1,
            .paritysetting = 0,
        };
        int error = csp_usart_open_and_add_kiss_interface(&conf, CSP_IF_KISS_DEFAULT_NAME, 0, &default_iface);
        if (error != CSP_ERR_NONE) {
            return NULL; // Replace exit with return for test purposes
        }
        default_iface->is_default = 1;
    }

    // Add logic for DEVICE_CAN and DEVICE_ZMQ if necessary
    // ...

    return default_iface;
}

// Server task function to handle incoming connections
static void server_task() {
    csp_socket_t sock = {0};
    csp_bind(&sock, CSP_ANY);
    csp_listen(&sock, 10);

    while (true) {
        csp_conn_t *conn = csp_accept(&sock, 10000);
        if (!conn) continue;

        csp_packet_t *packet;
        while ((packet = csp_read(conn, 50)) != NULL) {
            switch (csp_conn_dport(conn)) {
                case MY_SERVER_PORT:
                    csp_buffer_free(packet);
                    break;
                default:
                    csp_service_handler(packet);
                    break;
            }
        }
        csp_close(conn);
    }
}

FUZZ_TEST_SETUP() {
    csp_init();
    std::thread(server_task).detach();
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    csp_iface_t *default_iface;
    csp_usart_conf_t conf;
    conf.device = (char *)fdp.ConsumeBytesAsString(10).c_str();
    conf.baudrate = 115200;
    conf.databits = 8;
    conf.stopbits = 1;
    conf.paritysetting = 0;

    // Simulate adding an interface based on a random choice
    int device_choice = fdp.ConsumeIntegralInRange<int>(0, 2);
    switch (device_choice) {
    case 0: default_iface = add_interface(DEVICE_CAN, "can_device"); break;
    case 1: default_iface = add_interface(DEVICE_KISS, "kiss_device"); break;
    case 2: default_iface = add_interface(DEVICE_ZMQ, "zmq_device"); break;
    default: return;
    }

    csp_conn_t *conn = fdp.ConsumeBool() ? 
        csp_connect(CSP_PRIO_NORM, 0, MY_SERVER_PORT, 1000, CSP_O_NONE) : 
        csp_connect(CSP_PRIO_NORM, 1, MY_SERVER_PORT, 1000, CSP_O_NONE);

    if (conn == nullptr) {
        return;
    }

    // The fuzzer controls the packet data to be sent
    while (fdp.remaining_bytes() > 0) {
        auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
        if (packet_data.empty() || packet_data.size() > CSP_BUFFER_SIZE) {
            continue;
        }

        csp_packet_t *packet = csp_buffer_get(0);
        if (packet == nullptr) {
            break;
        }
        std::memcpy(packet->data, packet_data.data(), packet_data.size());
        packet->length = packet_data.size();
        csp_send(conn, packet);
    }

    if (fdp.ConsumeBool()) {
        csp_close(conn);
    }
}
