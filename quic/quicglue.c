/* quicglue.c — a small, clean C shim over ngtcp2 (QUIC transport) + GnuTLS
 * (QUIC-TLS via ngtcp2's crypto helper) + nghttp3 (HTTP/3).
 *
 * Compiled against the real system headers (so every ngtcp2/nghttp3 struct
 * layout, callback signature, and version macro is correct), it exposes a tiny
 * pull-based C API that the nimony reactor drives:
 *
 *   feed a UDP datagram in  ->  aq_process_read()
 *   pull outgoing datagrams ->  aq_flush()          (does the sendto itself)
 *   nearest timer / fire    ->  aq_timeout_ms() / aq_handle_timeout()
 *   server: take a request  ->  aq_take_request() ; answer -> aq_respond()
 *   client: response ready  ->  aq_client_done() / _status() / _body()
 *
 * All UDP I/O, connection-ID routing, TLS sessions, and timers live here in C;
 * nimony only owns the epoll wait on aq_fd(). This mirrors how the aoughwl stack
 * already FFIs OpenSSL (tls) and zlib (compress).
 *
 * Scope: TLS 1.3 handshake, one or more concurrent connections, HTTP/3
 * request/response with QPACK. No Retry/address-validation token and no 0-RTT
 * (a full but not exhaustive server). */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#define MAX_CONNS 64
#define MAX_STREAMS 64
#define MAX_CIDS 256
#define MAX_REQ 256
#define SEND_BUF 1452
#define SCIDLEN 16
#define DBG(...) do{ if(getenv("AQ_DEBUG")) fprintf(stderr, __VA_ARGS__);}while(0)

/* ---- streams ---------------------------------------------------------- */
typedef struct {
  int64_t id;
  int used;
  int fin_recv;          /* request stream fully received */
  int queued;            /* pushed to the request queue */
  char method[16]; int method_len;
  char path[512];  int path_len;
  int status;            /* client: response status */
  /* request/response body buffer (recv on server, recv on client) */
  char *rbody; int rbody_len; int rbody_cap;
  /* response body to send (server) */
  char *sbody; int sbody_len; int sbody_off;
  int has_response;
} Stream;

/* ---- a QUIC connection ------------------------------------------------ */
typedef struct Conn {
  int used;
  struct aq_ctx *ctx;
  ngtcp2_conn *conn;
  gnutls_session_t tls;
  ngtcp2_crypto_conn_ref cref;
  nghttp3_conn *h3;
  int handshake_done;
  int closed;
  uint8_t scid[NGTCP2_MAX_CIDLEN]; size_t scidlen;
  struct sockaddr_storage remote; socklen_t remotelen;
  struct sockaddr_storage local;  socklen_t locallen;
  Stream streams[MAX_STREAMS];
  int64_t ctrl_id, qpack_enc_id, qpack_dec_id;
} Conn;

/* ---- CID -> Conn routing table ---------------------------------------- */
typedef struct {
  uint8_t cid[NGTCP2_MAX_CIDLEN]; size_t len; Conn *conn;
} CidEntry;

/* ---- pending request handles (server) --------------------------------- */
typedef struct { Conn *conn; int64_t stream_id; int used; } ReqEntry;

typedef struct aq_ctx {
  int is_server;
  int fd;
  struct sockaddr_storage local; socklen_t locallen;
  struct sockaddr_storage peer;  socklen_t peerlen;   /* client: server addr */
  gnutls_certificate_credentials_t cred;
  Conn conns[MAX_CONNS];
  CidEntry cids[MAX_CIDS];
  ReqEntry reqs[MAX_REQ];
  /* client single-request state */
  char cli_authority[256];
  char cli_path[512];
  int64_t cli_stream;
  int cli_done;
} aq_ctx;

/* ====================================================================== */
static uint64_t timestamp(void) {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void rand_bytes(uint8_t *dest, size_t len) {
  gnutls_rnd(GNUTLS_RND_RANDOM, dest, len);
}

/* ---- CID table -------------------------------------------------------- */
static void cid_add(aq_ctx *c, const uint8_t *cid, size_t len, Conn *conn) {
  for (int i = 0; i < MAX_CIDS; i++) {
    if (!c->cids[i].conn) {
      memcpy(c->cids[i].cid, cid, len);
      c->cids[i].len = len; c->cids[i].conn = conn; return;
    }
  }
}
static void cid_del(aq_ctx *c, const uint8_t *cid, size_t len) {
  for (int i = 0; i < MAX_CIDS; i++)
    if (c->cids[i].conn && c->cids[i].len == len &&
        memcmp(c->cids[i].cid, cid, len) == 0) { c->cids[i].conn = NULL; return; }
}
static Conn *cid_find(aq_ctx *c, const uint8_t *cid, size_t len) {
  for (int i = 0; i < MAX_CIDS; i++)
    if (c->cids[i].conn && c->cids[i].len == len &&
        memcmp(c->cids[i].cid, cid, len) == 0) return c->cids[i].conn;
  return NULL;
}

static Conn *conn_alloc(aq_ctx *c) {
  for (int i = 0; i < MAX_CONNS; i++)
    if (!c->conns[i].used) { memset(&c->conns[i], 0, sizeof(Conn));
      c->conns[i].used = 1; c->conns[i].ctx = c; return &c->conns[i]; }
  return NULL;
}

static Stream *stream_get(Conn *cn, int64_t id, int create) {
  for (int i = 0; i < MAX_STREAMS; i++)
    if (cn->streams[i].used && cn->streams[i].id == id) return &cn->streams[i];
  if (!create) return NULL;
  for (int i = 0; i < MAX_STREAMS; i++)
    if (!cn->streams[i].used) { memset(&cn->streams[i], 0, sizeof(Stream));
      cn->streams[i].used = 1; cn->streams[i].id = id; return &cn->streams[i]; }
  return NULL;
}

static void rbody_append(Stream *s, const uint8_t *d, size_t n) {
  if (s->rbody_len + (int)n + 1 > s->rbody_cap) {
    int nc = s->rbody_cap ? s->rbody_cap * 2 : 4096;
    while (nc < s->rbody_len + (int)n + 1) nc *= 2;
    s->rbody = realloc(s->rbody, nc); s->rbody_cap = nc;
  }
  memcpy(s->rbody + s->rbody_len, d, n); s->rbody_len += n;
  s->rbody[s->rbody_len] = 0;
}

/* get_conn callback for ngtcp2 crypto (gnutls) */
static ngtcp2_conn *get_conn_cb(ngtcp2_crypto_conn_ref *ref) {
  return ((Conn *)ref->user_data)->conn;
}

/* ====================================================================== */
/* nghttp3 callbacks                                                        */
/* ====================================================================== */
static int h3_recv_header(nghttp3_conn *h3, int64_t stream_id,
                          int32_t token, nghttp3_rcbuf *name,
                          nghttp3_rcbuf *value, uint8_t flags,
                          void *user_data, void *stream_user_data) {
  (void)h3; (void)token; (void)flags;
  Conn *cn = user_data;
  Stream *s = stream_get(cn, stream_id, 1);
  if (!s) return 0;
  nghttp3_vec nv = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec vv = nghttp3_rcbuf_get_buf(value);
  if (cn->ctx->is_server) {
    if (nv.len == 7 && memcmp(nv.base, ":method", 7) == 0) {
      int n = vv.len < 15 ? (int)vv.len : 15;
      memcpy(s->method, vv.base, n); s->method_len = n;
    } else if (nv.len == 5 && memcmp(nv.base, ":path", 5) == 0) {
      int n = vv.len < 511 ? (int)vv.len : 511;
      memcpy(s->path, vv.base, n); s->path_len = n;
    }
  } else {
    if (nv.len == 7 && memcmp(nv.base, ":status", 7) == 0) {
      char tmp[8] = {0}; int n = vv.len < 7 ? (int)vv.len : 7;
      memcpy(tmp, vv.base, n); s->status = atoi(tmp);
    }
  }
  return 0;
}

static int h3_recv_data(nghttp3_conn *h3, int64_t stream_id,
                        const uint8_t *data, size_t datalen,
                        void *user_data, void *stream_user_data) {
  (void)h3; (void)stream_user_data;
  Conn *cn = user_data;
  Stream *s = stream_get(cn, stream_id, 1);
  if (s) rbody_append(s, data, datalen);
  return 0;
}

static void queue_request(aq_ctx *c, Conn *cn, int64_t stream_id) {
  for (int i = 0; i < MAX_REQ; i++)
    if (!c->reqs[i].used) { c->reqs[i].used = 1; c->reqs[i].conn = cn;
      c->reqs[i].stream_id = stream_id; return; }
}

static int h3_end_stream(nghttp3_conn *h3, int64_t stream_id,
                         void *user_data, void *stream_user_data) {
  (void)h3; (void)stream_user_data;
  Conn *cn = user_data;
  Stream *s = stream_get(cn, stream_id, 1);
  if (cn->ctx->is_server) {
    if (s && !s->queued) { s->queued = 1; queue_request(cn->ctx, cn, stream_id); }
  } else {
    cn->ctx->cli_done = 1;
  }
  return 0;
}

static int h3_stream_close(nghttp3_conn *h3, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
  (void)h3; (void)app_error_code; (void)stream_id;
  (void)user_data; (void)stream_user_data;
  return 0;
}

static int h3_stop_sending(nghttp3_conn *h3, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
  (void)h3; (void)app_error_code; (void)user_data; (void)stream_user_data;
  return 0;
}
static int h3_reset_stream(nghttp3_conn *h3, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
  (void)h3; (void)stream_id; (void)app_error_code;
  (void)user_data; (void)stream_user_data;
  return 0;
}

/* data reader: streams a stream's sbody buffer to nghttp3 */
static nghttp3_ssize resp_read_data(nghttp3_conn *h3, int64_t stream_id,
                                    nghttp3_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *user_data,
                                    void *stream_user_data) {
  (void)h3; (void)veccnt; (void)stream_user_data;
  Conn *cn = user_data;
  Stream *s = stream_get(cn, stream_id, 0);
  if (!s) { *pflags = NGHTTP3_DATA_FLAG_EOF; return 0; }
  int remain = s->sbody_len - s->sbody_off;
  if (remain <= 0) { *pflags = NGHTTP3_DATA_FLAG_EOF; return 0; }
  vec[0].base = (uint8_t *)(s->sbody + s->sbody_off);
  vec[0].len = remain;
  s->sbody_off += remain;
  *pflags = NGHTTP3_DATA_FLAG_EOF;
  return 1;
}

/* ====================================================================== */
/* ngtcp2 callbacks                                                         */
/* ====================================================================== */
static void ng_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx; rand_bytes(dest, destlen);
}

static int ng_get_new_cid(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  (void)conn;
  Conn *cn = user_data;
  rand_bytes(cid->data, cidlen); cid->datalen = cidlen;
  rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  cid_add(cn->ctx, cid->data, cidlen, cn);
  return 0;
}

static int ng_remove_cid(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                         void *user_data) {
  (void)conn;
  Conn *cn = user_data;
  cid_del(cn->ctx, cid->data, cid->datalen);
  return 0;
}

static int h3_setup_server(Conn *cn); /* fwd */
static int h3_setup_client(Conn *cn); /* fwd */

static int ng_handshake_completed(ngtcp2_conn *conn, void *user_data) {
  (void)conn;
  Conn *cn = user_data;
  cn->handshake_done = 1; DBG("handshake completed server=%d\n", cn->ctx->is_server);
  if (cn->ctx->is_server) return h3_setup_server(cn) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
  else return h3_setup_client(cn) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int ng_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
  (void)conn; (void)offset; (void)stream_user_data;
  Conn *cn = user_data;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
  if (!cn->h3) return 0;
  nghttp3_ssize n = nghttp3_conn_read_stream(cn->h3, stream_id, data, datalen, fin);
  if (n < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, (uint64_t)n);
  ngtcp2_conn_extend_max_offset(conn, (uint64_t)n);
  return 0;
}

static int ng_acked_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                                uint64_t offset, uint64_t datalen,
                                void *user_data, void *stream_user_data) {
  (void)conn; (void)offset; (void)stream_user_data;
  Conn *cn = user_data;
  if (cn->h3) nghttp3_conn_add_ack_offset(cn->h3, stream_id, datalen);
  return 0;
}

static int ng_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
  (void)conn; (void)stream_user_data;
  Conn *cn = user_data;
  if (cn->h3) {
    if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
      app_error_code = NGHTTP3_H3_NO_ERROR;
    nghttp3_conn_close_stream(cn->h3, stream_id, app_error_code);
  }
  return 0;
}

static int ng_stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t final_size, uint64_t app_error_code,
                           void *user_data, void *stream_user_data) {
  (void)conn; (void)final_size; (void)app_error_code; (void)stream_user_data;
  Conn *cn = user_data;
  if (cn->h3) nghttp3_conn_shutdown_stream_read(cn->h3, stream_id);
  return 0;
}

static int ng_extend_max_remote_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                                     void *user_data) {
  (void)conn; (void)max_streams; (void)user_data; return 0;
}

static void fill_callbacks(ngtcp2_callbacks *cb, int server) {
  memset(cb, 0, sizeof(*cb));
  cb->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cb->encrypt = ngtcp2_crypto_encrypt_cb;
  cb->decrypt = ngtcp2_crypto_decrypt_cb;
  cb->hp_mask = ngtcp2_crypto_hp_mask_cb;
  cb->update_key = ngtcp2_crypto_update_key_cb;
  cb->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cb->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  cb->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  cb->handshake_completed = ng_handshake_completed;
  cb->recv_stream_data = ng_recv_stream_data;
  cb->acked_stream_data_offset = ng_acked_stream_data;
  cb->stream_close = ng_stream_close;
  cb->stream_reset = ng_stream_reset;
  cb->rand = ng_rand;
  cb->get_new_connection_id = ng_get_new_cid;
  cb->remove_connection_id = ng_remove_cid;
  cb->extend_max_remote_streams_bidi = ng_extend_max_remote_bidi;
  if (server) {
    cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  } else {
    cb->client_initial = ngtcp2_crypto_client_initial_cb;
    cb->recv_retry = ngtcp2_crypto_recv_retry_cb;
  }
}

static void default_tp(ngtcp2_transport_params *p) {
  ngtcp2_transport_params_default(p);
  p->initial_max_streams_bidi = 100;
  p->initial_max_streams_uni = 3;
  p->initial_max_stream_data_bidi_local = 256 * 1024;
  p->initial_max_stream_data_bidi_remote = 256 * 1024;
  p->initial_max_stream_data_uni = 256 * 1024;
  p->initial_max_data = 1024 * 1024;
  p->max_idle_timeout = 30 * NGTCP2_SECONDS;
}

/* ====================================================================== */
/* HTTP/3 setup on handshake                                                */
/* ====================================================================== */
static const nghttp3_callbacks h3_srv_cbs = {
  NULL, /* acked_stream_data */
  h3_stream_close,
  h3_recv_data,
  NULL, /* deferred_consume */
  NULL, /* begin_headers */
  h3_recv_header,
  NULL, /* end_headers */
  NULL, /* begin_trailers */
  NULL, /* recv_trailer */
  NULL, /* end_trailers */
  h3_stop_sending,
  h3_end_stream,
  h3_reset_stream,
  NULL, /* shutdown */
};

static int open_uni(Conn *cn, int64_t *sid) {
  return ngtcp2_conn_open_uni_stream(cn->conn, sid, NULL);
}

static int h3_bind_streams(Conn *cn) {
  if (open_uni(cn, &cn->ctrl_id) != 0) return -1;
  if (nghttp3_conn_bind_control_stream(cn->h3, cn->ctrl_id) != 0) return -1;
  if (open_uni(cn, &cn->qpack_enc_id) != 0) return -1;
  if (open_uni(cn, &cn->qpack_dec_id) != 0) return -1;
  if (nghttp3_conn_bind_qpack_streams(cn->h3, cn->qpack_enc_id, cn->qpack_dec_id) != 0)
    return -1;
  return 0;
}

static int h3_setup_server(Conn *cn) {
  nghttp3_settings s; nghttp3_settings_default(&s);
  if (nghttp3_conn_server_new(&cn->h3, &h3_srv_cbs, &s, NULL, cn) != 0) return -1;
  return h3_bind_streams(cn);
}

static int h3_setup_client(Conn *cn) {
  nghttp3_settings s; nghttp3_settings_default(&s);
  if (nghttp3_conn_client_new(&cn->h3, &h3_srv_cbs, &s, NULL, cn) != 0) return -1;
  if (h3_bind_streams(cn) != 0) return -1;
  /* submit the GET request on a fresh client bidi stream */
  int64_t sid;
  if (ngtcp2_conn_open_bidi_stream(cn->conn, &sid, NULL) != 0) return -1;
  cn->ctx->cli_stream = sid;
  const char *auth = cn->ctx->cli_authority;
  const char *path = cn->ctx->cli_path;
  nghttp3_nv nva[4] = {
    {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":authority", (uint8_t *)auth, 10, strlen(auth), NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":path", (uint8_t *)path, 5, strlen(path), NGHTTP3_NV_FLAG_NONE},
  };
  if (nghttp3_conn_submit_request(cn->h3, sid, nva, 4, NULL, cn) != 0) return -1;
  return 0;
}

/* ====================================================================== */
/* path helper                                                              */
/* ====================================================================== */
static void make_path(ngtcp2_path *path, Conn *cn) {
  path->local.addr = (ngtcp2_sockaddr *)&cn->local;
  path->local.addrlen = cn->locallen;
  path->remote.addr = (ngtcp2_sockaddr *)&cn->remote;
  path->remote.addrlen = cn->remotelen;
  path->user_data = NULL;
}

/* ====================================================================== */
/* server: accept a new connection from an Initial packet                   */
/* ====================================================================== */
static int tls_server_session(Conn *cn) {
  if (gnutls_init(&cn->tls, GNUTLS_SERVER) != 0) return -1;
  if (gnutls_priority_set_direct(cn->tls,
        "NORMAL:-VERS-ALL:+VERS-TLS1.3:%DISABLE_TLS13_COMPAT_MODE", NULL) != 0)
    return -1;
  gnutls_credentials_set(cn->tls, GNUTLS_CRD_CERTIFICATE, cn->ctx->cred);
  gnutls_datum_t alpn = {(unsigned char *)"h3", 2};
  gnutls_alpn_set_protocols(cn->tls, &alpn, 1, GNUTLS_ALPN_MANDATORY);
  if (ngtcp2_crypto_gnutls_configure_server_session(cn->tls) != 0) return -1;
  cn->cref.get_conn = get_conn_cb; cn->cref.user_data = cn;
  gnutls_session_set_ptr(cn->tls, &cn->cref);
  return 0;
}

static Conn *server_accept(aq_ctx *c, const uint8_t *pkt, size_t pktlen,
                           struct sockaddr *ra, socklen_t ralen) {
  ngtcp2_pkt_hd hd;
  int _ar = ngtcp2_accept(&hd, pkt, pktlen);
  if (_ar != 0) { DBG("ngtcp2_accept rv=%d\n", _ar); return NULL; }
  Conn *cn = conn_alloc(c);
  if (!cn) return NULL;
  memcpy(&cn->remote, ra, ralen); cn->remotelen = ralen;
  memcpy(&cn->local, &c->local, c->locallen); cn->locallen = c->locallen;

  /* our source CID (what the client will use as DCID) */
  cn->scidlen = SCIDLEN; rand_bytes(cn->scid, cn->scidlen);

  ngtcp2_cid scid, dcid;
  memcpy(scid.data, cn->scid, cn->scidlen); scid.datalen = cn->scidlen;
  memcpy(dcid.data, hd.scid.data, hd.scid.datalen); dcid.datalen = hd.scid.datalen;

  ngtcp2_settings settings; ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp();
  ngtcp2_transport_params params; default_tp(&params);
  params.original_dcid = hd.dcid;

  ngtcp2_callbacks cbs; fill_callbacks(&cbs, 1);
  ngtcp2_path path; make_path(&path, cn);

  if (ngtcp2_conn_server_new(&cn->conn, &dcid, &scid, &path, hd.version,
                             &cbs, &settings, &params, NULL, cn) != 0) {
    DBG("conn_server_new failed\n"); cn->used = 0; return NULL;
  }
  if (tls_server_session(cn) != 0) { ngtcp2_conn_del(cn->conn); cn->used = 0; return NULL; }
  ngtcp2_conn_set_tls_native_handle(cn->conn, cn->tls);
  cid_add(c, cn->scid, cn->scidlen, cn);
  return cn;
}

/* ====================================================================== */
/* the write loop: pull packets from ngtcp2 (+ nghttp3) and sendto          */
/* ====================================================================== */
static void conn_close(aq_ctx *c, Conn *cn) {
  if (!cn->used || cn->closed) return;
  cn->closed = 1;
  cid_del(c, cn->scid, cn->scidlen);
  /* purge any cids pointing here */
  for (int i = 0; i < MAX_CIDS; i++) if (c->cids[i].conn == cn) c->cids[i].conn = NULL;
  if (cn->h3) { nghttp3_conn_del(cn->h3); cn->h3 = NULL; }
  if (cn->conn) { ngtcp2_conn_del(cn->conn); cn->conn = NULL; }
  if (cn->tls) { gnutls_deinit(cn->tls); cn->tls = NULL; }
  for (int i = 0; i < MAX_STREAMS; i++) {
    if (cn->streams[i].rbody) free(cn->streams[i].rbody);
    if (cn->streams[i].sbody) free(cn->streams[i].sbody);
  }
  cn->used = 0;
}

static int conn_write(aq_ctx *c, Conn *cn) {
  if (!cn->used || cn->closed || !cn->conn) return 0;
  uint8_t buf[SEND_BUF];
  ngtcp2_path path; make_path(&path, cn);
  ngtcp2_pkt_info pi; memset(&pi, 0, sizeof(pi));
  uint64_t ts = timestamp();

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_vec vec[16];
    nghttp3_ssize sveccnt = 0;
    if (cn->h3) {
      sveccnt = nghttp3_conn_writev_stream(cn->h3, &stream_id, &fin, vec, 16);
      if (sveccnt < 0) { conn_close(c, cn); return -1; }
    }
    ngtcp2_ssize ndatalen;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
        cn->conn, &path, &pi, buf, sizeof(buf), &ndatalen, flags, stream_id,
        (ngtcp2_vec *)vec, (size_t)sveccnt, ts);
    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_WRITE_MORE) {
        if (cn->h3 && ndatalen >= 0)
          nghttp3_conn_add_write_offset(cn->h3, stream_id, (size_t)ndatalen);
        continue;
      }
      DBG("writev_stream err=%zd %s\n", (ssize_t)nwrite, ngtcp2_strerror((int)nwrite)); conn_close(c, cn);
      return -1;
    }
    if (cn->h3 && ndatalen >= 0)
      nghttp3_conn_add_write_offset(cn->h3, stream_id, (size_t)ndatalen);
    if (nwrite == 0) break;   /* nothing more to send right now */
    sendto(c->fd, buf, (size_t)nwrite, 0,
           (struct sockaddr *)&cn->remote, cn->remotelen);
  }
  return 0;
}

/* ====================================================================== */
/* public API                                                               */
/* ====================================================================== */
static int set_nonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int make_udp(const char *host, uint16_t port,
                    struct sockaddr_storage *out, socklen_t *outlen, int server) {
  struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET; sa.sin_port = htons(port);
  inet_pton(AF_INET, host ? host : "127.0.0.1", &sa.sin_addr);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return -1;
  if (server) {
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    socklen_t l = sizeof(*out); getsockname(fd, (struct sockaddr *)out, &l); *outlen = l;
  } else {
    memcpy(out, &sa, sizeof(sa)); *outlen = sizeof(sa);
  }
  set_nonblock(fd);
  return fd;
}

aq_ctx *aq_server_new(const char *host, uint16_t port,
                      const char *cert, const char *key) {
  gnutls_global_init();
  aq_ctx *c = calloc(1, sizeof(aq_ctx));
  c->is_server = 1;
  if (gnutls_certificate_allocate_credentials(&c->cred) != 0) { free(c); return NULL; }
  if (gnutls_certificate_set_x509_key_file(c->cred, cert, key,
                                           GNUTLS_X509_FMT_PEM) < 0) {
    free(c); return NULL;
  }
  c->fd = make_udp(host, port, &c->local, &c->locallen, 1);
  if (c->fd < 0) { free(c); return NULL; }
  return c;
}

static int cli_verify(gnutls_session_t s) { (void)s; return 0; }  /* accept self-signed (test) */

aq_ctx *aq_client_new(const char *host, uint16_t port,
                      const char *authority, const char *path) {
  gnutls_global_init();
  aq_ctx *c = calloc(1, sizeof(aq_ctx));
  c->is_server = 0;
  gnutls_certificate_allocate_credentials(&c->cred);
  gnutls_certificate_set_verify_function(c->cred, cli_verify);
  c->fd = make_udp(host, port, &c->peer, &c->peerlen, 0);
  if (c->fd < 0) { free(c); return NULL; }
  /* local addr: let the OS pick; connect() so getsockname yields it */
  struct sockaddr_in la; memset(&la, 0, sizeof(la));
  la.sin_family = AF_INET; inet_pton(AF_INET, "127.0.0.1", &la.sin_addr);
  bind(c->fd, (struct sockaddr *)&la, sizeof(la));
  socklen_t ll = sizeof(c->local);
  getsockname(c->fd, (struct sockaddr *)&c->local, &ll); c->locallen = ll;
  snprintf(c->cli_authority, sizeof(c->cli_authority), "%s", authority);
  snprintf(c->cli_path, sizeof(c->cli_path), "%s", path);
  c->cli_stream = -1;
  return c;
}

static int tls_client_session(Conn *cn, const char *authority) {
  if (gnutls_init(&cn->tls, GNUTLS_CLIENT) != 0) return -1;
  gnutls_priority_set_direct(cn->tls,
      "NORMAL:-VERS-ALL:+VERS-TLS1.3:%DISABLE_TLS13_COMPAT_MODE", NULL);
  gnutls_credentials_set(cn->tls, GNUTLS_CRD_CERTIFICATE, cn->ctx->cred);
  gnutls_server_name_set(cn->tls, GNUTLS_NAME_DNS, authority, strlen(authority));
  gnutls_datum_t alpn = {(unsigned char *)"h3", 2};
  gnutls_alpn_set_protocols(cn->tls, &alpn, 1, GNUTLS_ALPN_MANDATORY);
  if (ngtcp2_crypto_gnutls_configure_client_session(cn->tls) != 0) return -1;
  cn->cref.get_conn = get_conn_cb; cn->cref.user_data = cn;
  gnutls_session_set_ptr(cn->tls, &cn->cref);
  return 0;
}

int aq_client_start(aq_ctx *c) {
  Conn *cn = conn_alloc(c);
  if (!cn) return -1;
  memcpy(&cn->remote, &c->peer, c->peerlen); cn->remotelen = c->peerlen;
  memcpy(&cn->local, &c->local, c->locallen); cn->locallen = c->locallen;

  ngtcp2_cid scid, dcid;
  scid.datalen = 16; rand_bytes(scid.data, scid.datalen);
  dcid.datalen = 16; rand_bytes(dcid.data, dcid.datalen);
  memcpy(cn->scid, scid.data, scid.datalen); cn->scidlen = scid.datalen;

  ngtcp2_settings settings; ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp();
  ngtcp2_transport_params params; default_tp(&params);
  ngtcp2_callbacks cbs; fill_callbacks(&cbs, 0);
  ngtcp2_path path; make_path(&path, cn);

  if (ngtcp2_conn_client_new(&cn->conn, &dcid, &scid, &path,
                             NGTCP2_PROTO_VER_V1, &cbs, &settings, &params,
                             NULL, cn) != 0) { cn->used = 0; return -1; }
  if (tls_client_session(cn, c->cli_authority) != 0) return -1;
  ngtcp2_conn_set_tls_native_handle(cn->conn, cn->tls);
  cid_add(c, cn->scid, cn->scidlen, cn);
  return conn_write(c, cn);
}

int aq_fd(aq_ctx *c) { return c->fd; }

int aq_process_read(aq_ctx *c) {
  uint8_t buf[65536];
  for (;;) {
    struct sockaddr_storage ra; socklen_t ralen = sizeof(ra);
    ssize_t n = recvfrom(c->fd, buf, sizeof(buf), 0, (struct sockaddr *)&ra, &ralen);
    if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; break; }
    if (n == 0) continue;
    ngtcp2_version_cid vc;
    int rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)n, SCIDLEN);
    if (rv != 0) { DBG("decode_version_cid rv=%d\n", rv); continue; }
    Conn *cn = cid_find(c, vc.dcid, vc.dcidlen);
    if (!cn) {
      if (c->is_server)
        cn = server_accept(c, buf, (size_t)n, (struct sockaddr *)&ra, ralen);
      if (!cn) continue;
    }
    memcpy(&cn->remote, &ra, ralen); cn->remotelen = ralen;
    ngtcp2_path path; make_path(&path, cn);
    ngtcp2_pkt_info pi; memset(&pi, 0, sizeof(pi));
    rv = ngtcp2_conn_read_pkt(cn->conn, &path, &pi, buf, (size_t)n, timestamp());
    if (rv != 0) { DBG("read_pkt rv=%d %s (server=%d)\n", rv, ngtcp2_strerror(rv), c->is_server); conn_close(c, cn); continue; }
  }
  /* generate any responses/acks */
  for (int i = 0; i < MAX_CONNS; i++)
    if (c->conns[i].used) conn_write(c, &c->conns[i]);
  return 0;
}

int aq_flush(aq_ctx *c) {
  for (int i = 0; i < MAX_CONNS; i++)
    if (c->conns[i].used) conn_write(c, &c->conns[i]);
  return 0;
}

long aq_timeout_ms(aq_ctx *c) {
  uint64_t now = timestamp();
  uint64_t best = UINT64_MAX;
  for (int i = 0; i < MAX_CONNS; i++) {
    if (!c->conns[i].used || !c->conns[i].conn) continue;
    uint64_t e = ngtcp2_conn_get_expiry(c->conns[i].conn);
    if (e < best) best = e;
  }
  if (best == UINT64_MAX) return -1;
  if (best <= now) return 0;
  uint64_t d = (best - now) / NGTCP2_MILLISECONDS;
  return (long)(d > 1000000 ? 1000000 : d);
}

int aq_handle_timeout(aq_ctx *c) {
  uint64_t now = timestamp();
  for (int i = 0; i < MAX_CONNS; i++) {
    Conn *cn = &c->conns[i];
    if (!cn->used || !cn->conn) continue;
    uint64_t e = ngtcp2_conn_get_expiry(cn->conn);
    if (e <= now) {
      if (ngtcp2_conn_handle_expiry(cn->conn, now) != 0) { conn_close(c, cn); continue; }
      conn_write(c, cn);
    }
  }
  return 0;
}

int aq_take_request(aq_ctx *c, uint64_t *req_id, char *method, int mcap,
                    char *path, int pcap) {
  for (int i = 0; i < MAX_REQ; i++) {
    if (c->reqs[i].used) {
      Conn *cn = c->reqs[i].conn;
      Stream *s = stream_get(cn, c->reqs[i].stream_id, 0);
      if (!s) { c->reqs[i].used = 0; continue; }
      int mn = s->method_len < mcap - 1 ? s->method_len : mcap - 1;
      int pn = s->path_len < pcap - 1 ? s->path_len : pcap - 1;
      memcpy(method, s->method, mn); method[mn] = 0;
      memcpy(path, s->path, pn); path[pn] = 0;
      *req_id = (uint64_t)i;
      return 1;
    }
  }
  return 0;
}

int aq_respond(aq_ctx *c, uint64_t req_id, int status, const char *ctype,
               const char *body, int body_len) {
  if (req_id >= MAX_REQ || !c->reqs[req_id].used) return -1;
  Conn *cn = c->reqs[req_id].conn;
  int64_t sid = c->reqs[req_id].stream_id;
  c->reqs[req_id].used = 0;
  Stream *s = stream_get(cn, sid, 0);
  if (!s || !cn->h3) return -1;
  s->sbody = malloc(body_len > 0 ? body_len : 1);
  if (body_len > 0) memcpy(s->sbody, body, body_len);
  s->sbody_len = body_len; s->sbody_off = 0; s->has_response = 1;

  char clen[32]; snprintf(clen, sizeof(clen), "%d", body_len);
  char st[8]; snprintf(st, sizeof(st), "%d", status);
  nghttp3_nv nva[3] = {
    {(uint8_t *)":status", (uint8_t *)st, 7, strlen(st), NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)"content-type", (uint8_t *)ctype, 12, strlen(ctype), NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)"content-length", (uint8_t *)clen, 14, strlen(clen), NGHTTP3_NV_FLAG_NONE},
  };
  nghttp3_data_reader dr; dr.read_data = resp_read_data;
  if (nghttp3_conn_submit_response(cn->h3, sid, nva, 3, &dr) != 0) return -1;
  conn_write(c, cn);
  return 0;
}

int aq_client_done(aq_ctx *c) {
  /* done when the response stream ended, or all conns gone */
  if (c->cli_done) return 1;
  for (int i = 0; i < MAX_CONNS; i++) if (c->conns[i].used) return 0;
  return 1;
}

int aq_client_status(aq_ctx *c) {
  for (int i = 0; i < MAX_CONNS; i++) {
    if (!c->conns[i].used) continue;
    Stream *s = stream_get(&c->conns[i], c->cli_stream, 0);
    if (s) return s->status;
  }
  return 0;
}

int aq_client_body(aq_ctx *c, char *buf, int cap) {
  for (int i = 0; i < MAX_CONNS; i++) {
    if (!c->conns[i].used) continue;
    Stream *s = stream_get(&c->conns[i], c->cli_stream, 0);
    if (s && s->rbody) {
      int n = s->rbody_len < cap ? s->rbody_len : cap;
      memcpy(buf, s->rbody, n); return n;
    }
  }
  return 0;
}

void aq_free(aq_ctx *c) {
  if (!c) return;
  for (int i = 0; i < MAX_CONNS; i++) if (c->conns[i].used) conn_close(c, &c->conns[i]);
  if (c->cred) gnutls_certificate_free_credentials(c->cred);
  if (c->fd >= 0) close(c->fd);
  free(c);
}
