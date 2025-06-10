#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

extern "C" {
    #include <csp/interfaces/csp_if_zmqhub.h>
}

#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

extern csp_conf_t csp_conf;

void start_dummy_server() {
    csp_socket_t sock = {0};
    csp_bind(&sock, CSP_ANY);
    csp_listen(&sock, 10);

    while (true) {
        csp_conn_t* conn;
        if ((conn = csp_accept(&sock, 10000)) != NULL) {
            csp_packet_t* packet;
            while ((packet = csp_read(conn, 50)) != NULL) {
                csp_buffer_free(packet);
            }
            csp_close(conn);
        }
    }
}

FUZZ_TEST_SETUP() {
    csp_init();
    std::thread server_thread(start_dummy_server);
    server_thread.detach();
}

FUZZ_TEST(const uint8_t* data, size_t size) {
    if (size < 4) return;

    FuzzedDataProvider fdp(data, size);
    csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);

    uint8_t address = fdp.ConsumeIntegral<uint8_t>();
    unsigned int timeout = fdp.ConsumeIntegral<uint8_t>();
    unsigned int ping_size = fdp.ConsumeIntegral<uint8_t>();
    csp_ping(address, timeout, ping_size, CSP_O_NONE);
}
