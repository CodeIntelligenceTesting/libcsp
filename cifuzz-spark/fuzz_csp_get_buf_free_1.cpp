#include <cassert>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_cmp.h>
#include <csp/arch/csp_time.h>
#include <cstring>
#include <thread>
#include <iostream>
#include <mutex>

// Macros for constants
#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

extern "C" {
    #include <csp/csp.h>
}
extern csp_conf_t csp_conf;

// Global mutex for safeguarding critical sections
std::mutex csp_mutex;

// Dummy server to simulate server behavior for the client interaction
void server() {
    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // Server logic or socket connection handling
    }
}

// Initialization setup for the fuzz test, starting a server thread
FUZZ_TEST_SETUP() {
    static std::thread server_thread(server);
    server_thread.detach();  // Detach server thread to run independently

    //csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2); // CSP version 1 or 2
    csp_init();
}

// The fuzzing test function
FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    
    // Fuzzing variables
    uint16_t node = fdp.ConsumeIntegral<uint16_t>();
    uint32_t timeout = fdp.ConsumeIntegral<uint32_t>();

    // Validation to prevent erratic behavior
    if (timeout > 10000) return;

    {
        // Ensure thread-safe operations by using mutex
        std::lock_guard<std::mutex> lock(csp_mutex);

        uint32_t buf_size;

        // Dummy packet setup to ensure proper initialization
        csp_packet_t packet;
        packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
        auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
        packet.length = packet_data.size();
        if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
            return;
        }
        std::memcpy(packet.data, packet_data.data(), packet_data.size());

        // Perform the buffer free operation
        int err = csp_get_buf_free(node, timeout, &buf_size);
        if (err == CSP_ERR_NONE) {
            csp_print_func("Free buffers operation success\n");
        } else {
            csp_print_func("Network error\n");
        }
    }
}
