/* test_quic.c — self-contained e2e: drive the shim's server and client in one
 * poll loop over localhost UDP. Proves the QUIC handshake + HTTP/3
 * request/response works before the nimony FFI is layered on. */
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
extern long aq_timeout_ms(aq_ctx*);
extern int aq_handle_timeout(aq_ctx*);
extern int aq_take_request(aq_ctx*, uint64_t*, char*, int, char*, int);
extern int aq_respond(aq_ctx*, uint64_t, int, const char*, const char*, int);
extern int aq_client_done(aq_ctx*);
extern int aq_client_status(aq_ctx*);
extern int aq_client_body(aq_ctx*, char*, int);
extern void aq_free(aq_ctx*);

int main(int argc, char **argv) {
  uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 8443;
  const char *cert = argc > 2 ? argv[2] : "cert.pem";
  const char *key  = argc > 3 ? argv[3] : "key.pem";

  aq_ctx *srv = aq_server_new("127.0.0.1", port, cert, key);
  if (!srv) { printf("server_new failed\n"); return 1; }
  aq_ctx *cli = aq_client_new("127.0.0.1", port, "localhost", "/hello");
  if (!cli) { printf("client_new failed\n"); return 1; }
  if (aq_client_start(cli) != 0) { printf("client_start failed\n"); return 1; }

  struct pollfd pfd[2];
  pfd[0].fd = aq_fd(srv); pfd[0].events = POLLIN;
  pfd[1].fd = aq_fd(cli); pfd[1].events = POLLIN;

  for (int iter = 0; iter < 2000; iter++) {
    poll(pfd, 2, 5);
    if (pfd[0].revents & POLLIN) aq_process_read(srv);
    if (pfd[1].revents & POLLIN) aq_process_read(cli);
    aq_handle_timeout(srv);
    aq_handle_timeout(cli);
    /* server answers any pending request */
    uint64_t rid; char method[16], path[512];
    while (aq_take_request(srv, &rid, method, sizeof method, path, sizeof path)) {
      char body[256];
      int n = snprintf(body, sizeof body, "hello h3: %s %s\n", method, path);
      aq_respond(srv, rid, 200, "text/plain", body, n);
    }
    aq_flush(srv); aq_flush(cli);
    if (aq_client_done(cli)) {
      char buf[1024]; int n = aq_client_body(cli, buf, sizeof buf - 1);
      buf[n] = 0;
      int status = aq_client_status(cli);
      printf("STATUS=%d\nBODY=%s", status, buf);
      fflush(stdout);
      aq_free(srv); aq_free(cli);
      return (status == 200 && n > 0) ? 0 : 2;
    }
  }
  printf("TIMEOUT: handshake/response did not complete\n");
  aq_free(srv); aq_free(cli);
  return 3;
}
