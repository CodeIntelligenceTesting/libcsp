#include <thread>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_cmp.h>
#include <csp/arch/csp_time.h>
#include <endian.h>

#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

extern "C" {
    extern csp_conf_t csp_conf;
}

// Mock server to simulate server-side responses
void mock_server() {
    // Long-running process to simulate server behavior
    while (true) {
        // In real application, server logic would go here.
    }
}

FUZZ_TEST_SETUP() {
    // Start the mock server in a new thread
    std::thread(mock_server).detach();
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Set the version of the CSP (CSP1 or CSP2)
    csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);
    auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);

    // Validate packet data size
    if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
        return;
    }

    uint16_t node = fdp.ConsumeIntegral<uint16_t>();
    uint32_t timeout = fdp.ConsumeIntegral<uint32_t>();
    uint32_t memfree;

    // Validate pointers and inputs before calling the target function
    if (csp_conf.version == 0) {
        return; // Ensure version is initialized
    }

    // Call the target function under test safely
    int result = csp_get_memfree(node, timeout, &memfree);

    // Avoid using undefined output. Assume logic here for handling results.
}
