#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_cmp.h>
#include <csp/arch/csp_time.h>
#include <thread>

// Dummy server function
void server() {
    while (1) {
        // This should ideally accept and process CSP connections
        // For now, it just runs indefinitely to simulate a server
    }
}

// Configuration for CSP - setup interfaces, and anything necessary
void setup_csp() {
    csp_buffer_init(); // Ensure CSP is initialized with default setup

    csp_init(); // Initialize CSP library
    
    // Any additional setup, such as opening interfaces, can be added here
}

FUZZ_TEST_SETUP() {
    setup_csp(); // Ensure CSP setup is done once
    std::thread(server).detach(); // Start the server logic on a separate thread
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create fuzzed input values
    uint16_t node = fdp.ConsumeIntegral<uint16_t>();
    uint32_t timeout = fdp.ConsumeIntegral<uint32_t>();
    uint32_t memfree = 0;

    // Check if node value and timeout are within expected range
    if (node > 0 && timeout > 0) {
        // Invoke the function under test
        int error_status = csp_get_memfree(node, timeout, &memfree);

        // Call auxiliary functions depending on the error status
        if (error_status == CSP_ERR_NONE) {
            csp_memfree(node, timeout);
        }
    }
}
