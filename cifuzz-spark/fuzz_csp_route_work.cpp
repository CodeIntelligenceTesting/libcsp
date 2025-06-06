#include <pthread.h>
#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
  #include <csp/csp.h>
  #include <csp/csp_debug.h>
}

#define CSP_BUFFER_SIZE 256

void* task_router(void*) {
    while (1) {
        csp_route_work();
    }
    return NULL;
}

void dummy_server(void) {
    while (1) {
        csp_route_work();
    }
}

static void* server_worker(void* param) {
    dummy_server();
    return NULL;
}

static int init_thread(void* (*routine)(void*)) {
    pthread_attr_t attributes;
    pthread_t handle;
    if (pthread_attr_init(&attributes) != 0) {
        return CSP_ERR_NOMEM;
    }
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    int ret = pthread_create(&handle, &attributes, routine, NULL);
    pthread_attr_destroy(&attributes);
    return ret == 0 ? CSP_ERR_NONE : ret;
}

FUZZ_TEST_SETUP() {
    csp_init();
    init_thread(server_worker);
}

FUZZ_TEST(const uint8_t* data, size_t size) {
    if (size < 1) return;

    FuzzedDataProvider fdp(data, size);
    
    uint8_t test_selector = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);

    switch (test_selector) {
        case 0: { // First fuzz case
            csp_packet_t packet;
            packet.id.flags = fdp.ConsumeIntegral<uint8_t>();

            auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
            packet.length = packet_data.size();

            if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
                return;
            }

            // Simulate sending the packet data here
            // csp_send_packet(packet);
            break;
        }

        case 1: { // Second fuzz case
            csp_packet_t packet;
            packet.id.flags = fdp.ConsumeIntegral<uint8_t>();
            auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE - 1);
            packet.length = packet_data.size();
            if (packet_data.size() == 0 || packet_data.size() > CSP_BUFFER_SIZE) {
                return;
            }

            // In a practical server-client setting, packet would be manipulated and sent
            csp_route_work();
            break;
        }
    }
}
