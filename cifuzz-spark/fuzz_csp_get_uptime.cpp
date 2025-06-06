#include <assert.h>
#include <cifuzz/cifuzz.h>
extern "C" {
  #include <csp/csp.h>
  #include <csp/csp_debug.h>
  #include <csp/csp_cmp.h>
  #include <csp/arch/csp_time.h>
}
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#define CSP_BUFFER_SIZE 256

// Dummy server function
void server() {
  // Initialize the CSP communication
  csp_init();
 
  while (1) {
    // Simulate server activity, this is a placeholder
    // Normally, this would handle CSP connections and packets
  }
}

FUZZ_TEST_SETUP() {
  // Launch the server in a separate thread
  std::thread server_thread(server);
  server_thread.detach();
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  // Fuzz inputs for the csp_get_uptime function
  uint16_t node = fdp.ConsumeIntegral<uint16_t>();
  uint32_t timeout = fdp.ConsumeIntegral<uint32_t>();
  uint32_t uptime;

  // Fuzz a packet to simulate client-side operations
  csp_packet_t packet;
  packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
  auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
  packet.length = packet_data.size();
  
  // Return if packet size is zero or greater than the buffer
  if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
    return;
  }

  // Copy fuzzed data into packet
  memcpy(packet.data, packet_data.data(), packet_data.size());

  // Call the function under test
  int result = csp_get_uptime(node, timeout, &uptime);

  // In the case the result is error, appropriate action based on responses could be considered.
  // But for the fuzzer, we just leave the execution as is to explore potential edge-cases.
}
