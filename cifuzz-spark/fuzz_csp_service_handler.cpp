#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_interface.h>
#include <pthread.h>

// Assumed buffer size constant, verify from project if it's defined
#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 256
#endif

/*
 * Basic server setup, listens and processes packets in a separate thread.
 */
void* basic_server(void*) {
    csp_socket_t sock = {0};
    csp_bind(&sock, CSP_ANY);
    csp_listen(&sock, 10);

    for (;;) {
        csp_conn_t *conn;
        if ((conn = csp_accept(&sock, 10000)) != NULL) {
            csp_packet_t *packet;
            while ((packet = csp_read(conn, 50)) != NULL) {
                csp_service_handler(packet);
            }
            csp_close(conn);
        }
    }
    return nullptr;
}

FUZZ_TEST_SETUP() {
    csp_init();
    pthread_t server_thread;
    pthread_create(&server_thread, nullptr, basic_server, nullptr);
    pthread_detach(server_thread); // Ensures the thread cleans up after itself
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Ensure we have enough data to form a valid packet before proceeding
    if (fdp.remaining_bytes() < sizeof(csp_packet_t)) {
        return;
    }

    // Construct the packet with fuzzed data
    csp_packet_t packet;
    packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
    auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
    packet.length = packet_data.size();
    if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
        return;
    }
    std::memcpy(packet.data, packet_data.data(), packet_data.size());

    // Pass the packet to the service handler
    csp_service_handler(&packet);
}

