#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/drivers/usart.h>
#include <csp/drivers/can_socketcan.h>
#include <csp/interfaces/csp_if_zmqhub.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>
#include <unistd.h>

static void server() {
    csp_socket_t sock = {0};
    csp_bind(&sock, CSP_ANY);
    csp_listen(&sock, 10);

    while (true) {
        csp_conn_t *conn = csp_accept(&sock, 10000);
        if (!conn) continue;

        csp_packet_t *packet;
        while ((packet = csp_read(conn, 50)) != NULL) {
            if (csp_conn_dport(conn) == 10) {
                csp_buffer_free(packet);
            } else {
                csp_service_handler(packet);
            }
        }
        csp_close(conn);
    }
}

FUZZ_TEST_SETUP() {
    csp_init();
    std::thread(server).detach();
    sleep(2);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    uint8_t addr = fdp.ConsumeIntegral<uint8_t>();
    csp_conn_t *conn = csp_connect(CSP_PRIO_NORM, addr, 10, 1000, CSP_O_NONE);
    if (!conn) return;

    csp_packet_t *packet = csp_buffer_get_always();
    if (!packet) return;

    size_t len = std::min(fdp.remaining_bytes(), static_cast<size_t>(256));
    fdp.ConsumeData(packet->data, len);
    packet->length = len;
    csp_send(conn, packet);
    csp_close(conn);
}
