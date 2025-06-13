#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstring>
#include <cstdlib>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/interfaces/csp_if_lo.h>
#include <pthread.h>

#define MY_SERVER_PORT 10
#ifndef CSP_BUFFER_SIZE
#define CSP_BUFFER_SIZE 1024
#endif

// Function to create a thread using the CSP model
static int csp_pthread_create(void *(*routine)(void *)) {
    pthread_attr_t attributes;
    pthread_t handle;
    int ret;
    if (pthread_attr_init(&attributes) != 0) {
        return CSP_ERR_NOMEM;
    }
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&handle, &attributes, routine, NULL);
    pthread_attr_destroy(&attributes);
    if (ret != 0) {
        return ret;
    }
    return CSP_ERR_NONE;
}

// Server thread function simulating server work
void *server_work(void *arg) {
    csp_socket_t socket = {0};
    csp_bind(&socket, CSP_ANY);
    csp_listen(&socket, 10);
    while (1) {
        csp_conn_t *conn = csp_accept(&socket, 50000);
        if (!conn) continue;

        csp_packet_t *packet;
        while ((packet = csp_read(conn, 50)) != nullptr) {
            csp_service_handler(packet);
        }
        csp_close(conn);
    }
    return nullptr;
}

// Router thread function to execute routing processes
void *router_work(void *arg) {
    while (1) {
        csp_route_work();
    }
}

// Initialization function using necessary CSP setup
FUZZ_TEST_SETUP() {
    csp_init();
    csp_pthread_create(router_work);
    csp_pthread_create(server_work);
}

// Main fuzz test function
FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    csp_conn_t *conn = nullptr;
    // CSP ports are typically in the range 0-6 7-> to trigger the default branch
    uint8_t dport = fdp.ConsumeIntegralInRange<uint8_t>(0, 7); 
    conn = csp_connect(CSP_PRIO_NORM, 0, dport, 1000, CSP_O_NONE);

    if (conn == nullptr) {
        return;
    }
    
    while (fdp.remaining_bytes() > 0) {
        auto packet_data = fdp.ConsumeBytes<uint8_t>(CSP_BUFFER_SIZE);
        if (packet_data.empty() || packet_data.size() > CSP_BUFFER_SIZE) {
            continue;
        }
        
        csp_packet_t *packet = csp_buffer_get_always();
        if (packet == nullptr) {
            break;
        }

        std::memcpy(packet->data, packet_data.data(), packet_data.size());
        packet->length = packet_data.size();
        packet->id.dport = dport;
        csp_send(conn, packet);
    }
    
    csp_close(conn);
}
