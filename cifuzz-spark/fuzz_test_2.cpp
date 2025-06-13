#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <csp/csp.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

extern "C" {
  #include <csp/csp_debug.h>
  #include <csp/drivers/usart.h>
  #include <csp/drivers/can_socketcan.h>
  #include <csp/interfaces/csp_if_zmqhub.h>
}

#define MY_SERVER_PORT 10

static int csp_pthread_create(void * (*routine)(void *)) {

	pthread_attr_t attributes;
	pthread_t handle;
	int ret;

	if (pthread_attr_init(&attributes) != 0) {
		return CSP_ERR_NOMEM;
	}
	/* no need to join with thread to free its resources */
	pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);

	ret = pthread_create(&handle, &attributes, routine, NULL);
	pthread_attr_destroy(&attributes);

	if (ret != 0) {
		return ret;
	}

	return CSP_ERR_NONE;
}

void* server_work(void* arg) {
    csp_socket_t socket = {0};
    csp_bind(&socket, CSP_ANY);
    csp_listen(&socket, 10);

    while (1) {
        csp_conn_t* conn = csp_accept(&socket, 50000);
        if (!conn) {
            continue;
        }

        csp_packet_t* packet;
        while ((packet = csp_read(conn, 50)) != nullptr) {
            if (csp_conn_dport(conn) == MY_SERVER_PORT) {
                csp_buffer_free(packet);
            } else {
                csp_service_handler(packet);
            }
        }
        csp_close(conn);
    }
    return nullptr;
}

void *router_work(void *arg) {
    while (1) {
		csp_route_work();
	}
}

FUZZ_TEST_SETUP() {
    csp_init();
    csp_pthread_create(router_work);
    csp_pthread_create(server_work);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    if (!data || size == 0) return;

    FuzzedDataProvider fdp(data, size);
    uint8_t srv_address = fdp.ConsumeIntegral<uint8_t>();
    uint8_t port = fdp.ConsumeIntegral<uint8_t>();

    csp_conn_t* conn = csp_connect(CSP_PRIO_NORM, srv_address, port, 1000, CSP_O_NONE);
    if (conn) {
        csp_packet_t* packet = csp_buffer_get_always();
        if (packet) {
            size_t usable_length = fdp.remaining_bytes();
            if (usable_length > 0 && usable_length < CSP_BUFFER_SIZE) {
                memcpy(packet->data, fdp.ConsumeBytes<uint8_t>(usable_length).data(), usable_length);
                packet->length = usable_length;
                csp_send(conn, packet);
            } else {
                csp_buffer_free(packet);
            }
        }
        csp_close(conn);
        usleep(10000);
    }
}
