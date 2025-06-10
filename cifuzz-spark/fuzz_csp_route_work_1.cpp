#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <pthread.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstring>
#include <thread>

#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

extern csp_conf_t csp_conf;

static void * task_router(void * param) {
    while (1) {
        csp_route_work();
    }
    return NULL;
}

// Function to be run on a separate thread for the server
void server_func() {
    while (true) {
        csp_route_work();
    }
}

FUZZ_TEST_SETUP() {
    // Start the router task on a separate thread using pthreads
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, task_router, nullptr);

    // Start the server function on a separate thread using std::thread
    std::thread server_thread_cpp(server_func);
    server_thread_cpp.detach();
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    if (size < 1) return;

    FuzzedDataProvider fdp(data, size);

    // Use the first byte to decide which fuzz logic to use
    uint8_t test_selector = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);

    switch (test_selector) {
        case 0: {
            // Code path from the first fuzz test

            // Set up CSP configuration
            csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);

            // Create a packet from fuzzed data
            csp_packet_t packet;
            packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
            auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);

            // Ensure valid packet data length
            if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
                return;
            }

            packet.length = packet_data.size();
            std::memcpy(packet.data, packet_data.data(), packet_data.size());

            csp_route_work();
            break;
        }

        case 1: {
            // Code path from the second fuzz test

            // Set up CSP configuration
            csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);

            // Create a packet from fuzzed data
            csp_packet_t packet;
            packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
            auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);

            // Ensure valid packet data length
            if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
                return;
            }

            packet.length = packet_data.size();
            std::memcpy(packet.data, packet_data.data(), packet_data.size());

            // For fuzzing, send the packet through a mock function or existing channel
            // Here, you'd replace with a function sending packets if available
            break;
        }

        default:
            return; // Graceful exit if the selector byte is out of range
    }
}
