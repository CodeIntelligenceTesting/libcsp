#include <cassert>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <csp/csp.h>
#include <thread>
#include <cstring>

#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

extern csp_conf_t csp_conf;

// Dummy server function that runs continuously
void server() {
    csp_init();  // Initialize CSP
    
    while (1) {
        // Server loop to process requests can be implemented here
        // Actual socket creation and handling is removed due to absence of `csp_socket()` function
    }
}

// FUZZ_TEST_SETUP is used to start server thread
FUZZ_TEST_SETUP() {
    std::thread(server).detach();
}

// FUZZ_TEST is the main entry point for fuzz data consumption
FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    
    csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);  // version 1 or 2

    uint8_t prio = fdp.ConsumeIntegral<uint8_t>();
    uint16_t dest = fdp.ConsumeIntegral<uint16_t>();
    uint8_t port = fdp.ConsumeIntegral<uint8_t>();
    uint32_t timeout = fdp.ConsumeIntegral<uint32_t>();
    uint32_t opts = fdp.ConsumeIntegral<uint32_t>();

    std::vector<uint8_t> outbuf = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
    // Create inbuf with a realistic size needed for testing
    std::vector<uint8_t> inbuf(CSP_BUFFER_SIZE);

    // Conduct transaction with the randomized data
    csp_transaction_w_opts(prio, dest, port, timeout, outbuf.data(), outbuf.size(), inbuf.data(), inbuf.size(), opts);
}
