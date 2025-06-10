#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <csp/csp_types.h>
#include <cstring> // for std::memcpy

#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

extern csp_conf_t csp_conf;

// Dummy connection struct example, modify as needed based on your project specifics
struct csp_conn_s_complete {
    uint8_t state;
    // Add other fields if necessary
};

// Use an alias for the complete definition
typedef struct csp_conn_s_complete csp_conn_t;

FUZZ_TEST_SETUP() {
    // One-time initialization logic, if necessary
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    csp_conf.version = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);

    // Ensure adequate bytes for fuzzing
    if (fdp.remaining_bytes() < sizeof(csp_conn_s_complete)) {
        return;
    }

    // Setup the connection
    csp_conn_t conn;
    conn.state = fdp.ConsumeIntegral<uint8_t>();

    // Define other necessary parameters
    unsigned int datasize = fdp.ConsumeIntegralInRange<unsigned int>(1, CSP_BUFFER_SIZE);
    unsigned int mtu = fdp.ConsumeIntegralInRange<unsigned int>(1, CSP_BUFFER_SIZE);
    unsigned int timeout = fdp.ConsumeIntegralInRange<unsigned int>(0, 5000);

    // Consume fuzzer data
    std::vector<uint8_t> csp_data = fdp.ConsumeBytes<uint8_t>(datasize);

    // Prevent execution with improper payload sizes
    if (csp_data.empty() || datasize > CSP_BUFFER_SIZE) {
        return;
    }

    // Execute the target function
    csp_sfp_send(&conn, csp_data.data(), datasize, mtu, timeout);
}
