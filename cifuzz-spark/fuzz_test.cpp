#include <csp/csp.h>
#include <csp/csp_crc32.h>
#include <csp/crypto/csp_hmac.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <assert.h>
#include <algorithm>

// The necessary headers for the implementation should be included here. 
// Check the library paths if any headers are not found, they might need adjustments in include paths.

extern "C" {
    #include <csp/csp_iflist.h>
    #include <csp/csp_debug.h>
    #include <csp/crypto/csp_hmac.h>

#include <string.h>

#include <csp/csp_buffer.h>
#include <csp/crypto/csp_sha1.h>
}


FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    csp_iface_t iface;
    iface.rx_error = 0;
    iface.autherr = 0;

    uint32_t security_opts = fdp.ConsumeIntegralInRange<uint32_t>(0, (CSP_SO_HMACREQ | CSP_SO_CRC32REQ));

    csp_packet_t packet;
    packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
    auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
    packet.length = packet_data.size();
    if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
        return;
    }
    std::memcpy(packet.data, packet_data.data(), packet_data.size());
    csp_hmac_verify(&packet, false);
}
