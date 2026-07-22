/* test_wt.c — WebTransport over HTTP/3: the client opens a WT session with an
 * extended CONNECT (:protocol=webtransport), sends a WT datagram; the server
 * echoes it on the session; the client receives it. Exercises the full path:
 * H3 SETTINGS (enable_connect_protocol + h3_datagram), extended CONNECT, and
 * H3-datagram framing (quarter-stream-id flow prefix) over QUIC datagrams. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <stdint.h>

typedef struct aq_ctx aq_ctx;
extern aq_ctx *aq_server_new(const char*, uint16_t, const char*, const char*);
extern aq_ctx *aq_client_new(const char*, uint16_t, const char*, const char*);
extern int aq_client_wt_connect(aq_ctx*);
extern int aq_client_wt_ready(aq_ctx*);
extern int aq_client_wt_send_datagram(aq_ctx*, const char*, int);
extern int aq_wt_send_datagram(aq_ctx*, uint64_t, const char*, int);
extern int aq_client_start(aq_ctx*);
extern int aq_fd(aq_ctx*);
extern int aq_process_read(aq_ctx*);
extern int aq_flush(aq_ctx*);
extern int aq_handle_timeout(aq_ctx*);
extern int aq_take_datagram(aq_ctx*, char*, int, uint64_t*);
extern void aq_free(aq_ctx*);

int main(int argc, char **argv) {
  uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 8443;
  const char *cert = argc > 2 ? argv[2] : "cert.pem";
  const char *key  = argc > 3 ? argv[3] : "key.pem";

  aq_ctx *srv = aq_server_new("127.0.0.1", port, cert, key);
  aq_ctx *cli = aq_client_new("127.0.0.1", port, "localhost", "/wt");
  if (!srv || !cli) { printf("setup failed\n"); return 1; }
  aq_client_wt_connect(cli);
  aq_client_start(cli);

  struct pollfd pfd[2];
  pfd[0].fd = aq_fd(srv); pfd[0].events = POLLIN;
  pfd[1].fd = aq_fd(cli); pfd[1].events = POLLIN;

  int sent = 0;
  for (int iter = 0; iter < 4000; iter++) {
    poll(pfd, 2, 5);
    if (pfd[0].revents & POLLIN) aq_process_read(srv);
    if (pfd[1].revents & POLLIN) aq_process_read(cli);
    aq_handle_timeout(srv); aq_handle_timeout(cli);

    if (!sent && aq_client_wt_ready(cli)) {
      aq_client_wt_send_datagram(cli, "wt-hello", 8);
      sent = 1;
      printf("WT_SESSION=established\n"); fflush(stdout);
    }

    char b[2048]; uint64_t tok;
    int n = aq_take_datagram(srv, b, sizeof b, &tok);
    if (n > 0) aq_wt_send_datagram(srv, tok, b, n);     /* echo on the session */

    int cn = aq_take_datagram(cli, b, sizeof b - 1, &tok);
    if (cn > 0) {
      b[cn] = 0;
      printf("WT_DGRAM_ECHO=%s\n", b); fflush(stdout);
      aq_free(srv); aq_free(cli);
      return (cn == 8 && memcmp(b, "wt-hello", 8) == 0) ? 0 : 2;
    }
    aq_flush(srv); aq_flush(cli);
  }
  printf("TIMEOUT: WebTransport datagram did not round-trip\n");
  aq_free(srv); aq_free(cli);
  return 3;
}
