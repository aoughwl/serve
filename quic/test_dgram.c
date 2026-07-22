/* test_dgram.c — RFC 9221 QUIC datagram round-trip: client sends an unreliable
 * datagram, server echoes it back on the same connection, client receives it. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <stdint.h>

typedef struct aq_ctx aq_ctx;
extern aq_ctx *aq_server_new(const char*, uint16_t, const char*, const char*);
extern aq_ctx *aq_client_new(const char*, uint16_t, const char*, const char*);
extern int aq_client_start(aq_ctx*);
extern int aq_fd(aq_ctx*);
extern int aq_process_read(aq_ctx*);
extern int aq_flush(aq_ctx*);
extern int aq_handle_timeout(aq_ctx*);
extern int aq_take_datagram(aq_ctx*, char*, int, uint64_t*);
extern int aq_send_datagram(aq_ctx*, uint64_t, const char*, int);
extern int aq_client_send_datagram(aq_ctx*, const char*, int);
extern void aq_free(aq_ctx*);

int main(int argc, char **argv) {
  uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 8443;
  const char *cert = argc > 2 ? argv[2] : "cert.pem";
  const char *key  = argc > 3 ? argv[3] : "key.pem";

  aq_ctx *srv = aq_server_new("127.0.0.1", port, cert, key);
  aq_ctx *cli = aq_client_new("127.0.0.1", port, "localhost", "/");
  if (!srv || !cli) { printf("setup failed\n"); return 1; }
  aq_client_start(cli);
  aq_client_send_datagram(cli, "ping-datagram", 13);   /* queued until handshake */

  struct pollfd pfd[2];
  pfd[0].fd = aq_fd(srv); pfd[0].events = POLLIN;
  pfd[1].fd = aq_fd(cli); pfd[1].events = POLLIN;

  for (int iter = 0; iter < 3000; iter++) {
    poll(pfd, 2, 5);
    if (pfd[0].revents & POLLIN) aq_process_read(srv);
    if (pfd[1].revents & POLLIN) aq_process_read(cli);
    aq_handle_timeout(srv); aq_handle_timeout(cli);

    /* server echoes any datagram back to its origin connection */
    char b[2048]; uint64_t tok;
    int n = aq_take_datagram(srv, b, sizeof b, &tok);
    if (n > 0) { aq_send_datagram(srv, tok, b, n); }

    /* client checks for the echo */
    int cn = aq_take_datagram(cli, b, sizeof b - 1, &tok);
    if (cn > 0) {
      b[cn] = 0;
      printf("DGRAM_ECHO=%s\n", b);
      fflush(stdout);
      aq_free(srv); aq_free(cli);
      return (cn == 13 && memcmp(b, "ping-datagram", 13) == 0) ? 0 : 2;
    }
    aq_flush(srv); aq_flush(cli);
  }
  printf("TIMEOUT: no datagram echo\n");
  aq_free(srv); aq_free(cli);
  return 3;
}
