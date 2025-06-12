#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include <csp/csp.h>
  #include <csp/csp_debug.h>
  #include <csp/csp_buffer.h>  // To ensure csp_buffer_get() and other functions are visible
}

#define SERVER_PORT 10
#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

void server_function() {
    csp_socket_t sock = {0};
    csp_bind(&sock, CSP_ANY);
    csp_listen(&sock, 10);

    while (1) {
        csp_conn_t *conn = csp_accept(&sock, 10000);
        if (!conn) continue;

        csp_packet_t *packet;
        while ((packet = csp_read(conn, 50)) != nullptr) {
            csp_service_handler(packet);
            csp_buffer_free(packet);
        }
        csp_close(conn);
    }
}

FUZZ_TEST_SETUP() {
  // Start the server in a separate thread
  std::thread server_thread(server_function);
  server_thread.detach();
  // Initialize CSP
  csp_init();
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    // Use FuzzedDataProvider to manage input data
    FuzzedDataProvider fdp(data, size);

    // Allocate a CSP buffer using the CSP API to ensure correct alignment and buffer handling
    csp_packet_t *packet = csp_buffer_get(CSP_BUFFER_SIZE);
    if (packet == nullptr) {
        return; // Return early if buffer allocation fails
    }

    packet->id.flags = fdp.ConsumeIntegral<uint8_t>();
    auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
    packet->length = packet_data.size();

    // Ensure packet data size is within limits
    if (packet_data.empty() || packet_data.size() > CSP_BUFFER_SIZE) {
        csp_buffer_free(packet);
        return;
    }

    // Copy the data into the packet's buffer
    std::memcpy(packet->data, packet_data.data(), packet_data.size());

    // Simulate handling of the packet
    csp_service_handler(packet);

    // Free the allocated packet buffer
    csp_buffer_free(packet);
}
