#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <endian.h>

extern "C" {
    #include <csp/csp.h>
    #include <csp/csp_debug.h>
    #include <csp/csp_cmp.h>
    #include <csp/arch/csp_time.h>
}

// Initialize the CSP library
static void initialize_csp() {
    csp_init(); // Initialize default inner workings of CSP
}

FUZZ_TEST_SETUP() {
    initialize_csp();
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    if (fdp.remaining_bytes() < sizeof(uint16_t) + sizeof(uint32_t)) {
        return;
    }

    // Consume the required inputs
    uint16_t node = fdp.ConsumeIntegral<uint16_t>();
    uint32_t timeout = fdp.ConsumeIntegral<uint32_t>();
    uint32_t buf_size;

    // Perform the function under test
    int result = csp_get_buf_free(node, timeout, &buf_size);

    // Handle the result
    if (result == CSP_ERR_NONE) {
        // Do something if needed, in this case we're just covering errors
    } else {
        // Handle any error scenarios, like logging if necessary
    }
}
