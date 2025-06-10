#include <cassert>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_cmp.h>
#include <csp/arch/csp_time.h>

#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

extern csp_conf_t csp_conf;

// Dummy server implementation
void serverTask() {
    while (true) {
        // Simulate server operations
    }
}

// Initialize fuzz test
FUZZ_TEST_SETUP() {
    std::thread(serverTask).detach();
}

// Execute fuzz test
FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2); // CSP version 1 or 2

    uint16_t node = fdp.ConsumeIntegral<uint16_t>();
    uint32_t timeout = fdp.ConsumeIntegral<uint32_t>();

    // Validate the inputs & prepare packet
    csp_packet_t packet;
    packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
    auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
    packet.length = packet_data.size();
    if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
        return;
    }
    std::memcpy(packet.data, packet_data.data(), packet_data.size());

    // Query uptime
    uint32_t uptime;
    int err = csp_get_uptime(node, timeout, &uptime);
    if (err != CSP_ERR_NONE) return;
}
