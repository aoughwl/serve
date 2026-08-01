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

/* Fixed capacities. Overridable at build time (-DMAX_CONNS=…) until they become
 * runtime configuration; every one of them counts its overflow in AqStats
 * rather than dropping silently. */
#ifndef MAX_CONNS
#define MAX_CONNS 64
#endif
#ifndef MAX_STREAMS
#define MAX_STREAMS 64
#endif
#ifndef MAX_WT
#define MAX_WT 32
#endif
#ifndef MAX_CIDS
#define MAX_CIDS 256
#endif
#ifndef MAX_REQ
#define MAX_REQ 256
#endif
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
  char path[2048]; int path_len;
  char protocol[24]; int protocol_len;   /* extended-CONNECT :protocol */
  int status;            /* client: response status */
  /* request/response body buffer (recv on server, recv on client) */
  char *rbody; int rbody_len; int rbody_cap;
  /* response body to send (server) */
  char *sbody; int sbody_len; int sbody_off;
  int has_response;
} Stream;

/* ---- WebTransport streams --------------------------------------------- */
/* A WebTransport stream is an ordinary QUIC stream whose *initiator* prefixes it
 * with a signal: on a bidi stream the frame type 0x41, on a uni stream the
 * stream type 0x54, each followed by a varint session id (the CONNECT stream id
 * divided by 4). Everything after that prefix is opaque application payload —
 * it never reaches nghttp3, so we route these streams ourselves. */
#define WT_BIDI_SIGNAL 0x41
#define WT_UNI_SIGNAL  0x54

typedef struct {
  int used;
  int64_t id;
  int64_t session;
  int is_uni;
  int incoming;       /* opened by the peer */
  int hdr_done;       /* the signal prefix has been parsed (in) / built (out) */
  int rejected;       /* classified as a plain H3 stream, not WebTransport */
  int taken;          /* handed to the application by aq_wt_take_stream */
  uint8_t pre[16]; int pre_len;         /* prefix bytes held for classification */
  char *rbuf; int rlen, rcap, roff;     /* received payload */
  int fin;                              /* peer finished the stream */
  char *sbuf; int slen, soff, scap;     /* payload to send (prefix included) */
  int send_fin, fin_sent;
} WtStream;

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
  int wt_active; int64_t wt_session;     /* WebTransport session stream */
  WtStream wt[MAX_WT];                   /* WebTransport streams on it */
  char *odg[8]; int odg_len[8]; int odg_head, odg_n;   /* outgoing datagrams */
} Conn;

/* ---- CID -> Conn routing table ---------------------------------------- */
typedef struct {
  uint8_t cid[NGTCP2_MAX_CIDLEN]; size_t len; Conn *conn;
} CidEntry;

/* ---- pending request handles (server) --------------------------------- */
typedef struct { Conn *conn; int64_t stream_id; int used; } ReqEntry;

/* ---- drop counters ----------------------------------------------------- */
typedef struct {
  uint64_t tx_send;        /* sendto() failed (EAGAIN on a full send buffer…) */
  uint64_t tx_dgram;       /* outgoing datagram queue full */
  uint64_t rx_dgram;       /* incoming datagram queue full */
  uint64_t conns;          /* MAX_CONNS reached, connection refused */
  uint64_t cids;           /* CID routing table full */
  uint64_t reqs;           /* request queue full */
  uint64_t truncated;      /* a request path/method did not fit its buffer */
} AqStats;

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
  char cli_method[8];
  char *cli_body; int cli_body_len;
  int64_t cli_stream;
  int cli_done;
  int cli_wt, cli_wt_ready, cli_wt_submitted;   /* WebTransport client */
  /* incoming datagrams (from any connection) */
  struct { int conn_idx; char *data; int len; int used; } idg[128];
  /* every bounded resource in here can fill up. When one does the packet or
   * request is dropped — that is unavoidable with fixed capacities, but it must
   * never be invisible. Each drop is counted here and readable via aq_stats. */
  AqStats stats;
} aq_ctx;

/* ====================================================================== */
static uint64_t timestamp(void) {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

/* QUIC variable-length integers (RFC 9000 §16) — used for the H3-datagram
 * flow-id (a WebTransport datagram is varint(session_stream_id/4) + payload). */
static size_t varint_decode(const uint8_t *p, size_t len, uint64_t *val) {
  if (len < 1) return 0;
  size_t n = (size_t)1 << (p[0] >> 6);
  if (len < n) return 0;
  uint64_t v = p[0] & 0x3f;
  for (size_t i = 1; i < n; i++) v = (v << 8) | p[i];
  *val = v; return n;
}
static size_t varint_encode(uint8_t *p, uint64_t v) {
  if (v < 64) { p[0] = (uint8_t)v; return 1; }
  if (v < 16384) { p[0] = 0x40 | (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }
  if (v < 1073741824ULL) {
    p[0] = 0x80 | (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; return 4;
  }
  for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
  p[0] |= 0xc0; return 8;
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
  c->stats.cids++;
  DBG("cid table full (%d) — connection will lose a routing entry\n", MAX_CIDS);
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

#if AQ_WEBTRANSPORT
/* ---- WebTransport stream table ---------------------------------------- */
static WtStream *wt_find(Conn *cn, int64_t id) {
  for (int i = 0; i < MAX_WT; i++)
    if (cn->wt[i].used && cn->wt[i].id == id) return &cn->wt[i];
  return NULL;
}

static WtStream *wt_alloc(Conn *cn, int64_t id, int incoming) {
  for (int i = 0; i < MAX_WT; i++)
    if (!cn->wt[i].used) {
      memset(&cn->wt[i], 0, sizeof(WtStream));
      cn->wt[i].used = 1; cn->wt[i].id = id; cn->wt[i].incoming = incoming;
      cn->wt[i].is_uni = (id & 0x2) != 0;
      cn->wt[i].session = cn->wt_session;
      return &cn->wt[i];
    }
  return NULL;
}

static void wt_rappend(WtStream *w, const uint8_t *d, size_t n) {
  if (n == 0) return;
  if (w->rlen + (int)n > w->rcap) {
    int nc = w->rcap ? w->rcap * 2 : 4096;
    while (nc < w->rlen + (int)n) nc *= 2;
    w->rbuf = realloc(w->rbuf, nc); w->rcap = nc;
  }
  memcpy(w->rbuf + w->rlen, d, n); w->rlen += (int)n;
}

static void wt_sappend(WtStream *w, const uint8_t *d, size_t n) {
  if (n == 0) return;
  int need = w->slen + (int)n;
  if (need > w->scap) {
    int nc = w->scap ? w->scap * 2 : 4096;
    while (nc < need) nc *= 2;
    w->sbuf = realloc(w->sbuf, nc); w->scap = nc;
  }
  memcpy(w->sbuf + w->slen, d, n); w->slen = need;
}

/* Feed freshly-received stream bytes to a (possible) WebTransport stream.
 * Returns 1 when the bytes belong to WebTransport and were consumed, 0 when the
 * stream turns out to be a plain HTTP/3 stream (`w->rejected` is then set and
 * the held prefix has NOT been consumed — the caller replays it into nghttp3). */
static int wt_ingest(WtStream *w, const uint8_t *data, size_t datalen, int fin) {
  const uint8_t *p = data; size_t n = datalen;
  if (!w->hdr_done) {
    while (n > 0 && w->pre_len < (int)sizeof(w->pre)) {
      w->pre[w->pre_len++] = *p++; n--;
    }
    uint64_t type = 0, sess = 0;
    size_t c1 = varint_decode(w->pre, (size_t)w->pre_len, &type);
    if (c1 == 0) return 1;               /* need more bytes to classify */
    uint64_t want = w->is_uni ? WT_UNI_SIGNAL : WT_BIDI_SIGNAL;
    if (type != want) { w->rejected = 1; return 0; }
    size_t c2 = varint_decode(w->pre + c1, (size_t)w->pre_len - c1, &sess);
    if (c2 == 0) return 1;               /* session id still incomplete */
    w->hdr_done = 1;
    w->session = (int64_t)(sess * 4);
    int left = w->pre_len - (int)(c1 + c2);
    if (left > 0) wt_rappend(w, w->pre + c1 + c2, (size_t)left);
    w->pre_len = 0;
  }
  wt_rappend(w, p, n);
  if (fin) w->fin = 1;
  return 1;
}
#endif

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
      if ((int)vv.len > n) {
        cn->ctx->stats.truncated++;
        DBG(":method truncated %zu -> %d bytes\n", vv.len, n);
      }
      memcpy(s->method, vv.base, n); s->method_len = n;
    } else if (nv.len == 5 && memcmp(nv.base, ":path", 5) == 0) {
      int cap = (int)sizeof(s->path) - 1;
      int n = (int)vv.len < cap ? (int)vv.len : cap;
      if ((int)vv.len > n) {
        cn->ctx->stats.truncated++;
        DBG(":path truncated %zu -> %d bytes\n", vv.len, n);
      }
      memcpy(s->path, vv.base, n); s->path_len = n;
    } else if (nv.len == 9 && memcmp(nv.base, ":protocol", 9) == 0) {
      int n = vv.len < 23 ? (int)vv.len : 23;
      memcpy(s->protocol, vv.base, n); s->protocol_len = n;
    }
  } else {
    if (nv.len == 7 && memcmp(nv.base, ":status", 7) == 0) {
      char tmp[8] = {0}; int n = vv.len < 7 ? (int)vv.len : 7;
      memcpy(tmp, vv.base, n); s->status = atoi(tmp);
      if (cn->ctx->cli_wt && s->status == 200) {
        cn->ctx->cli_wt_ready = 1;
        /* the CONNECT stream IS the session — record it like the server does so
         * the WebTransport stream paths are symmetric on both ends. */
        cn->wt_active = 1; cn->wt_session = stream_id;
      }
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
  c->stats.reqs++;
  DBG("request queue full (%d) — dropping stream %lld\n", MAX_REQ,
      (long long)stream_id);
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

static int conn_write(aq_ctx *c, Conn *cn); /* fwd */
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
#if AQ_WEBTRANSPORT
  /* WebTransport streams are routed here, never into nghttp3. A peer-initiated
   * stream is classified from its first bytes; one we opened ourselves is
   * already in the table (and carries no signal prefix in this direction). */
  if (cn->wt_active && stream_id != cn->wt_session) {
    WtStream *w = wt_find(cn, stream_id);
    int peer = cn->ctx->is_server ? ((stream_id & 1) == 0) : ((stream_id & 1) == 1);
    if (!w && peer) w = wt_alloc(cn, stream_id, 1);
    if (w && !w->rejected) {
      int before = w->pre_len;
      if (wt_ingest(w, data, datalen, fin)) {
        ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
        ngtcp2_conn_extend_max_offset(conn, datalen);
        return 0;
      }
      /* Not WebTransport after all. `w->pre` holds the stream's opening bytes —
       * replay all of them into HTTP/3, then fall through with what is left of
       * this call (which may be nothing, in which case only `fin` carries over).
       * Bytes held by earlier calls already got their flow-control credit. */
      if (w->pre_len > 0 &&
          nghttp3_conn_read_stream(cn->h3, stream_id, w->pre,
                                   (size_t)w->pre_len, 0) < 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
      size_t took = (size_t)(w->pre_len - before);
      ngtcp2_conn_extend_max_stream_offset(conn, stream_id, took);
      ngtcp2_conn_extend_max_offset(conn, took);
      data += took; datalen -= took;
    }
  }
#endif
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
#if AQ_WEBTRANSPORT
  { WtStream *w = wt_find(cn, stream_id);
    if (w && !w->rejected) { w->fin = 1; return 0; }   /* nghttp3 never saw it */ }
#endif
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

static int conn_index(aq_ctx *c, Conn *cn) {
  for (int i = 0; i < MAX_CONNS; i++) if (&c->conns[i] == cn) return i;
  return -1;
}

static int ng_recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                            const uint8_t *data, size_t datalen, void *user_data) {
  (void)conn; (void)flags;
  Conn *cn = user_data;
  aq_ctx *c = cn->ctx;
  const uint8_t *p = data; size_t plen = datalen;
#if AQ_WEBTRANSPORT
  if (cn->wt_active || (!c->is_server && c->cli_wt_ready)) {
    uint64_t flow; size_t consumed = varint_decode(data, datalen, &flow);
    if (consumed > 0) { p = data + consumed; plen = datalen - consumed; }
  }
#endif
  for (int i = 0; i < 128; i++) {
    if (!c->idg[i].used) {
      c->idg[i].used = 1;
      c->idg[i].conn_idx = conn_index(c, cn);
      c->idg[i].data = malloc(plen > 0 ? plen : 1);
      memcpy(c->idg[i].data, p, plen);
      c->idg[i].len = (int)plen;
      return 0;
    }
  }
  /* datagrams are unreliable by contract, so dropping one is legal — but the
   * application still has to be able to see that it happened. */
  c->stats.rx_dgram++;
  DBG("incoming datagram queue full (128) — dropped %zu bytes\n", plen);
  return 0;
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
  cb->recv_datagram = ng_recv_datagram;
  if (server) {
    cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  } else {
    cb->client_initial = ngtcp2_crypto_client_initial_cb;
    cb->recv_retry = ngtcp2_crypto_recv_retry_cb;
  }
}

/* ---- transport parameters as runtime configuration ---------------------
 *
 * These eight values were literals in default_tp, so a deployment could not
 * touch a single one of them: not the flow-control windows, not the idle
 * timeout, not the stream budgets -- and the stream budget in particular is
 * not a detail, since 3 H3 control streams once ate the whole of it.
 *
 * A field of -1 means "keep the built-in default", which is deliberately NOT
 * the same as 0: 0 is a real, meaningful value for max_datagram_frame_size
 * (it disables RFC 9221 datagrams, and therefore WebTransport datagrams).
 * Collapsing the two would make "leave datagrams alone" indistinguishable
 * from "turn datagrams off". */
#define AQ_KEEP (-1)

typedef struct {
  int64_t max_streams_bidi;
  int64_t max_streams_uni;
  int64_t stream_data_bidi_local;
  int64_t stream_data_bidi_remote;
  int64_t stream_data_uni;
  int64_t max_data;
  int64_t max_idle_ms;
  int64_t max_datagram_size;
} aq_config;

static aq_config g_cfg = { AQ_KEEP, AQ_KEEP, AQ_KEEP, AQ_KEEP,
                           AQ_KEEP, AQ_KEEP, AQ_KEEP, AQ_KEEP };

void aq_set_config(const aq_config *c) {
  if (c) g_cfg = *c;
  else {
    aq_config keep = { AQ_KEEP, AQ_KEEP, AQ_KEEP, AQ_KEEP,
                       AQ_KEEP, AQ_KEEP, AQ_KEEP, AQ_KEEP };
    g_cfg = keep;
  }
}

void aq_get_config(aq_config *out) {
  if (out) *out = g_cfg;
}

/* The built-in defaults, readable rather than buried in the assignment. */
void aq_default_config(aq_config *out) {
  if (!out) return;
  out->max_streams_bidi = 100;
  out->max_streams_uni = 100;   /* 3 H3 control streams + WebTransport uni */
  out->stream_data_bidi_local = 256 * 1024;
  out->stream_data_bidi_remote = 256 * 1024;
  out->stream_data_uni = 256 * 1024;
  out->max_data = 1024 * 1024;
  out->max_idle_ms = 30 * 1000;
  out->max_datagram_size = 65535;   /* RFC 9221 unreliable datagrams */
}

static void default_tp(ngtcp2_transport_params *p) {
  aq_config d;
  aq_default_config(&d);
  ngtcp2_transport_params_default(p);
  p->initial_max_streams_bidi =
      g_cfg.max_streams_bidi == AQ_KEEP ? (uint64_t)d.max_streams_bidi
                                        : (uint64_t)g_cfg.max_streams_bidi;
  p->initial_max_streams_uni =
      g_cfg.max_streams_uni == AQ_KEEP ? (uint64_t)d.max_streams_uni
                                       : (uint64_t)g_cfg.max_streams_uni;
  p->initial_max_stream_data_bidi_local =
      g_cfg.stream_data_bidi_local == AQ_KEEP
          ? (uint64_t)d.stream_data_bidi_local
          : (uint64_t)g_cfg.stream_data_bidi_local;
  p->initial_max_stream_data_bidi_remote =
      g_cfg.stream_data_bidi_remote == AQ_KEEP
          ? (uint64_t)d.stream_data_bidi_remote
          : (uint64_t)g_cfg.stream_data_bidi_remote;
  p->initial_max_stream_data_uni =
      g_cfg.stream_data_uni == AQ_KEEP ? (uint64_t)d.stream_data_uni
                                       : (uint64_t)g_cfg.stream_data_uni;
  p->initial_max_data =
      g_cfg.max_data == AQ_KEEP ? (uint64_t)d.max_data
                                : (uint64_t)g_cfg.max_data;
  p->max_idle_timeout =
      (ngtcp2_duration)(g_cfg.max_idle_ms == AQ_KEEP ? d.max_idle_ms
                                                     : g_cfg.max_idle_ms) *
      NGTCP2_MILLISECONDS;
  p->max_datagram_frame_size =
      g_cfg.max_datagram_size == AQ_KEEP ? (uint64_t)d.max_datagram_size
                                         : (uint64_t)g_cfg.max_datagram_size;
}

/* ====================================================================== */
/* HTTP/3 setup on handshake                                                */
/* ====================================================================== */
#if AQ_WEBTRANSPORT
/* keeps a WebTransport session stream open: EOF (no body) but not end-stream. */
static nghttp3_ssize wt_read_data(nghttp3_conn *h3, int64_t stream_id,
                                  nghttp3_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *user_data,
                                  void *stream_user_data) {
  (void)h3; (void)stream_id; (void)vec; (void)veccnt;
  (void)user_data; (void)stream_user_data;
  *pflags = NGHTTP3_DATA_FLAG_EOF | NGHTTP3_DATA_FLAG_NO_END_STREAM;
  return 0;
}

/* server: an extended-CONNECT with :protocol=webtransport establishes a WT
 * session — reply 200 and keep the CONNECT stream open as the session. */
static int h3_end_headers(nghttp3_conn *h3, int64_t stream_id, int fin,
                          void *user_data, void *stream_user_data) {
  (void)h3; (void)fin; (void)stream_user_data;
  Conn *cn = user_data;
  if (!cn->ctx->is_server) return 0;
  Stream *s = stream_get(cn, stream_id, 0);
  if (s && s->method_len == 7 && memcmp(s->method, "CONNECT", 7) == 0 &&
      s->protocol_len >= 12 && memcmp(s->protocol, "webtransport", 12) == 0) {
    cn->wt_active = 1; cn->wt_session = stream_id;
    nghttp3_nv nva[1] = {
      {(uint8_t *)":status", (uint8_t *)"200", 7, 3, NGHTTP3_NV_FLAG_NONE}};
    nghttp3_data_reader dr; dr.read_data = wt_read_data;
    nghttp3_conn_submit_response(cn->h3, stream_id, nva, 1, &dr);
    conn_write(cn->ctx, cn);
  }
  return 0;
}

/* client: submit the WT extended-CONNECT once the server's SETTINGS confirm
 * enable_connect_protocol (the correct H3 WebTransport sequence). */
static int h3_recv_settings(nghttp3_conn *h3, const nghttp3_settings *settings,
                            void *user_data) {
  (void)h3; (void)settings;
  Conn *cn = user_data;
  aq_ctx *c = cn->ctx;
  if (c->is_server || !c->cli_wt || c->cli_wt_submitted) return 0;
  c->cli_wt_submitted = 1;
  int64_t sid;
  if (ngtcp2_conn_open_bidi_stream(cn->conn, &sid, NULL) != 0) return 0;
  c->cli_stream = sid;
  const char *auth = c->cli_authority;
  const char *path = c->cli_path;
  nghttp3_nv nva[5] = {
    {(uint8_t *)":method", (uint8_t *)"CONNECT", 7, 7, NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":protocol", (uint8_t *)"webtransport", 9, 12, NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":authority", (uint8_t *)auth, 10, strlen(auth), NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":path", (uint8_t *)path, 5, strlen(path), NGHTTP3_NV_FLAG_NONE},
  };
  nghttp3_data_reader dr; dr.read_data = wt_read_data;
  nghttp3_conn_submit_request(cn->h3, sid, nva, 5, &dr, cn);
  conn_write(c, cn);
  return 0;
}
#endif

static const nghttp3_callbacks h3_srv_cbs = {
  .stream_close = h3_stream_close,
  .recv_data = h3_recv_data,
  .recv_header = h3_recv_header,
  .stop_sending = h3_stop_sending,
  .end_stream = h3_end_stream,
  .reset_stream = h3_reset_stream,
#if AQ_WEBTRANSPORT
  .end_headers = h3_end_headers,
  .recv_settings = h3_recv_settings,
#endif
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
#if AQ_WEBTRANSPORT
  s.enable_connect_protocol = 1;
  s.h3_datagram = 1;
#endif
  if (nghttp3_conn_server_new(&cn->h3, &h3_srv_cbs, &s, NULL, cn) != 0) return -1;
  return h3_bind_streams(cn);
}

static int h3_setup_client(Conn *cn) {
  nghttp3_settings s; nghttp3_settings_default(&s);
#if AQ_WEBTRANSPORT
  s.h3_datagram = 1;
#endif
  if (nghttp3_conn_client_new(&cn->h3, &h3_srv_cbs, &s, NULL, cn) != 0) return -1;
  if (h3_bind_streams(cn) != 0) return -1;
  if (cn->ctx->cli_wt) return 0;   /* WT CONNECT is submitted from recv_settings */
  /* submit the GET request on a fresh client bidi stream */
  int64_t sid;
  if (ngtcp2_conn_open_bidi_stream(cn->conn, &sid, NULL) != 0) return -1;
  cn->ctx->cli_stream = sid;
  aq_ctx *ctx = cn->ctx;
  const char *auth = ctx->cli_authority;
  const char *path = ctx->cli_path;
  const char *meth = ctx->cli_method;
  nghttp3_nv nva[4] = {
    {(uint8_t *)":method", (uint8_t *)meth, 7, strlen(meth), NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":authority", (uint8_t *)auth, 10, strlen(auth), NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)":path", (uint8_t *)path, 5, strlen(path), NGHTTP3_NV_FLAG_NONE},
  };
  nghttp3_data_reader dr; dr.read_data = resp_read_data;
  const nghttp3_data_reader *drp = NULL;
  if (ctx->cli_body && ctx->cli_body_len > 0) {
    Stream *rs = stream_get(cn, sid, 1);
    if (rs) {
      rs->sbody = malloc(ctx->cli_body_len);
      memcpy(rs->sbody, ctx->cli_body, ctx->cli_body_len);
      rs->sbody_len = ctx->cli_body_len; rs->sbody_off = 0;
      drp = &dr;
    }
  }
  if (nghttp3_conn_submit_request(cn->h3, sid, nva, 4, drp, cn) != 0) return -1;
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
  if (!cn) {
    c->stats.conns++;
    DBG("connection table full (%d) — refusing new connection\n", MAX_CONNS);
    return NULL;
  }
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
/* One place where packets actually leave. ngtcp2 has already decided this
 * packet may be sent, so a failure here is the kernel's send buffer, not
 * congestion: QUIC will retransmit, but the loss must still be countable
 * rather than silent. */
static void udp_send(aq_ctx *c, Conn *cn, const uint8_t *buf, size_t len) {
  ssize_t n;
  do {
    n = sendto(c->fd, buf, len, 0,
               (struct sockaddr *)&cn->remote, cn->remotelen);
  } while (n < 0 && errno == EINTR);
  if (n < 0) {
    c->stats.tx_send++;
    DBG("sendto failed: %s (%zu bytes)\n", strerror(errno), len);
  }
}

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
  for (int i = 0; i < 8; i++) if (cn->odg[i]) { free(cn->odg[i]); cn->odg[i] = NULL; }
  for (int i = 0; i < MAX_WT; i++) {
    if (cn->wt[i].rbuf) { free(cn->wt[i].rbuf); cn->wt[i].rbuf = NULL; }
    if (cn->wt[i].sbuf) { free(cn->wt[i].sbuf); cn->wt[i].sbuf = NULL; }
    cn->wt[i].used = 0;
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
    udp_send(c, cn, buf, (size_t)nwrite);
  }
#if AQ_WEBTRANSPORT
  /* WebTransport stream payload: written straight onto its QUIC stream, since
   * nghttp3 knows nothing about these streams. One packet per call (no
   * WRITE_MORE coalescing) — correctness first, and WT payloads are bulk data
   * that fills packets anyway. */
  for (int i = 0; i < MAX_WT; i++) {
    WtStream *w = &cn->wt[i];
    if (!w->used || w->rejected) continue;
    while (w->soff < w->slen || (w->send_fin && !w->fin_sent)) {
      size_t remain = (size_t)(w->slen - w->soff);
      ngtcp2_vec v;
      v.base = (uint8_t *)(w->sbuf + w->soff);
      v.len = remain;
      uint32_t sflags = NGTCP2_WRITE_STREAM_FLAG_NONE;
      if (w->send_fin) sflags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      ngtcp2_ssize ndatalen = 0;
      ngtcp2_ssize nw = ngtcp2_conn_writev_stream(
          cn->conn, &path, &pi, buf, sizeof(buf), &ndatalen, sflags, w->id,
          remain > 0 ? &v : NULL, remain > 0 ? 1 : 0, ts);
      if (nw < 0) {
        if (nw == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
            nw == NGTCP2_ERR_STREAM_SHUT_WR || nw == NGTCP2_ERR_STREAM_NOT_FOUND)
          break;
        DBG("wt writev err=%zd %s\n", (ssize_t)nw, ngtcp2_strerror((int)nw));
        conn_close(c, cn);
        return -1;
      }
      if (ndatalen > 0) w->soff += (int)ndatalen;
      if (nw == 0) break;               /* congestion/flow limited for now */
      udp_send(c, cn, buf, (size_t)nw);
      /* ngtcp2 only carries the FIN once the whole offered buffer went out */
      if (w->send_fin && (ngtcp2_ssize)remain == (ndatalen > 0 ? ndatalen : 0))
        w->fin_sent = 1;
    }
  }
#endif
  /* drain queued outgoing datagrams (only once the handshake can carry them) */
  while (cn->handshake_done && cn->odg_n > 0) {
    int h = cn->odg_head;
    ngtcp2_vec v; v.base = (uint8_t *)cn->odg[h]; v.len = (size_t)cn->odg_len[h];
    int accepted = 0;
    ngtcp2_ssize nw = ngtcp2_conn_writev_datagram(
        cn->conn, &path, &pi, buf, sizeof(buf), &accepted,
        NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &v, 1, ts);
    if (nw < 0) break;
    if (nw > 0)
      udp_send(c, cn, buf, (size_t)nw);
    if (accepted) {
      free(cn->odg[h]); cn->odg[h] = NULL;
      cn->odg_head = (h + 1) % 8; cn->odg_n--;
    } else {
      break;   /* congestion/flow limited — retry on the next write */
    }
    if (nw == 0) break;
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
  snprintf(c->cli_method, sizeof(c->cli_method), "GET");
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

int aq_client_post(aq_ctx *c, const char *body, int len) {
  snprintf(c->cli_method, sizeof(c->cli_method), "POST");
  c->cli_body = malloc(len > 0 ? len : 1);
  if (len > 0) memcpy(c->cli_body, body, len);
  c->cli_body_len = len;
  return 0;
}

int aq_request_body(aq_ctx *c, uint64_t req_id, char *buf, int cap) {
  if (req_id >= MAX_REQ || !c->reqs[req_id].used) return 0;
  Conn *cn = c->reqs[req_id].conn;
  Stream *s = stream_get(cn, c->reqs[req_id].stream_id, 0);
  if (!s || !s->rbody) return 0;
  int n = s->rbody_len < cap ? s->rbody_len : cap;
  memcpy(buf, s->rbody, n);
  return n;
}

static int enqueue_dgram(Conn *cn, const char *data, int len) {
  if (cn->odg_n >= 8) {
    cn->ctx->stats.tx_dgram++;
    DBG("outgoing datagram queue full (8) — dropping %d bytes\n", len);
    return -1;
  }
  int slot = (cn->odg_head + cn->odg_n) % 8;
  cn->odg[slot] = malloc(len > 0 ? len : 1);
  if (len > 0) memcpy(cn->odg[slot], data, len);
  cn->odg_len[slot] = len; cn->odg_n++;
  return 0;
}

int aq_take_datagram(aq_ctx *c, char *buf, int cap, uint64_t *conn_token) {
  for (int i = 0; i < 128; i++) {
    if (c->idg[i].used) {
      int n = c->idg[i].len < cap ? c->idg[i].len : cap;
      memcpy(buf, c->idg[i].data, n);
      *conn_token = (uint64_t)c->idg[i].conn_idx;
      free(c->idg[i].data); c->idg[i].data = NULL; c->idg[i].used = 0;
      return n;
    }
  }
  return 0;
}

int aq_send_datagram(aq_ctx *c, uint64_t conn_token, const char *data, int len) {
  if (conn_token >= MAX_CONNS || !c->conns[conn_token].used) return -1;
  return enqueue_dgram(&c->conns[conn_token], data, len);
}

int aq_client_send_datagram(aq_ctx *c, const char *data, int len) {
  for (int i = 0; i < MAX_CONNS; i++)
    if (c->conns[i].used) return enqueue_dgram(&c->conns[i], data, len);
  return -1;
}

int aq_client_wt_connect(aq_ctx *c) { c->cli_wt = 1; return 0; }
int aq_client_wt_ready(aq_ctx *c) { return c->cli_wt_ready; }

int aq_wt_send_datagram(aq_ctx *c, uint64_t conn_token, const char *data, int len) {
#if AQ_WEBTRANSPORT
  if (conn_token >= MAX_CONNS || !c->conns[conn_token].used) return -1;
  Conn *cn = &c->conns[conn_token];
  if (!cn->wt_active) return -1;
  uint8_t hdr[8]; size_t hn = varint_encode(hdr, (uint64_t)(cn->wt_session / 4));
  char *buf = malloc(hn + (size_t)len);
  memcpy(buf, hdr, hn); memcpy(buf + hn, data, len);
  int rv = enqueue_dgram(cn, buf, (int)hn + len);
  free(buf); return rv;
#else
  (void)c; (void)conn_token; (void)data; (void)len; return -1;
#endif
}

int aq_client_wt_send_datagram(aq_ctx *c, const char *data, int len) {
#if AQ_WEBTRANSPORT
  for (int i = 0; i < MAX_CONNS; i++) {
    if (!c->conns[i].used) continue;
    Conn *cn = &c->conns[i];
    uint8_t hdr[8]; size_t hn = varint_encode(hdr, (uint64_t)(c->cli_stream / 4));
    char *buf = malloc(hn + (size_t)len);
    memcpy(buf, hdr, hn); memcpy(buf + hn, data, len);
    int rv = enqueue_dgram(cn, buf, (int)hn + len);
    free(buf); return rv;
  }
#endif
  (void)c; (void)data; (void)len; return -1;
}

/* ---- drop counters ----------------------------------------------------- */
int aq_stats(aq_ctx *c, uint64_t *out, int n) {
  /* order matches the AqStats fields and quic.nim's QuicStats */
  uint64_t v[7] = {c->stats.tx_send, c->stats.tx_dgram, c->stats.rx_dgram,
                   c->stats.conns, c->stats.cids, c->stats.reqs,
                   c->stats.truncated};
  int k = n < 7 ? n : 7;
  for (int i = 0; i < k; i++) out[i] = v[i];
  return k;
}

/* ---- WebTransport streams (bidi + uni) -------------------------------- */
int aq_conn_token(aq_ctx *c) {
  /* the first live connection — a client has exactly one, so this is how a
   * client names its connection for the shared WebTransport stream API */
  for (int i = 0; i < MAX_CONNS; i++) if (c->conns[i].used) return i;
  return -1;
}

#if AQ_WEBTRANSPORT
static Conn *wt_conn(aq_ctx *c, uint64_t tok) {
  if (tok >= MAX_CONNS || !c->conns[tok].used) return NULL;
  Conn *cn = &c->conns[tok];
  return cn->wt_active ? cn : NULL;
}
#endif

int64_t aq_wt_open_stream(aq_ctx *c, uint64_t conn_token, int uni) {
#if AQ_WEBTRANSPORT
  Conn *cn = wt_conn(c, conn_token);
  if (!cn) return -1;
  int64_t sid = -1;
  int rv = uni ? ngtcp2_conn_open_uni_stream(cn->conn, &sid, NULL)
               : ngtcp2_conn_open_bidi_stream(cn->conn, &sid, NULL);
  if (rv != 0) return -1;
  WtStream *w = wt_alloc(cn, sid, 0);
  if (!w) return -1;
  w->hdr_done = 1;       /* we emit the signal prefix; nothing to parse inbound */
  w->is_uni = uni ? 1 : 0;
  w->session = cn->wt_session;
  uint8_t hdr[16]; size_t hn = 0;
  hn += varint_encode(hdr, uni ? WT_UNI_SIGNAL : WT_BIDI_SIGNAL);
  hn += varint_encode(hdr + hn, (uint64_t)(cn->wt_session / 4));
  wt_sappend(w, hdr, hn);
  conn_write(c, cn);
  return sid;
#else
  (void)c; (void)conn_token; (void)uni; return -1;
#endif
}

int aq_wt_stream_send(aq_ctx *c, uint64_t conn_token, int64_t stream_id,
                      const char *data, int len, int fin) {
#if AQ_WEBTRANSPORT
  Conn *cn = wt_conn(c, conn_token);
  if (!cn) return -1;
  WtStream *w = wt_find(cn, stream_id);
  if (!w || w->rejected) return -1;
  if (w->is_uni && w->incoming) return -1;      /* peer's uni stream: read-only */
  if (len > 0) wt_sappend(w, (const uint8_t *)data, (size_t)len);
  if (fin) w->send_fin = 1;
  conn_write(c, cn);
  return 0;
#else
  (void)c; (void)conn_token; (void)stream_id; (void)data; (void)len; (void)fin;
  return -1;
#endif
}

int aq_wt_take_stream(aq_ctx *c, uint64_t *conn_token, int64_t *stream_id,
                      int *uni) {
#if AQ_WEBTRANSPORT
  for (int i = 0; i < MAX_CONNS; i++) {
    Conn *cn = &c->conns[i];
    if (!cn->used || !cn->wt_active) continue;
    for (int j = 0; j < MAX_WT; j++) {
      WtStream *w = &cn->wt[j];
      if (!w->used || w->taken || w->rejected || !w->incoming || !w->hdr_done)
        continue;
      w->taken = 1;
      *conn_token = (uint64_t)i; *stream_id = w->id; *uni = w->is_uni;
      return 1;
    }
  }
#else
  (void)c; (void)conn_token; (void)stream_id; (void)uni;
#endif
  return 0;
}

int aq_wt_stream_recv(aq_ctx *c, uint64_t conn_token, int64_t stream_id,
                      char *buf, int cap) {
#if AQ_WEBTRANSPORT
  Conn *cn = wt_conn(c, conn_token);
  if (!cn) return 0;
  WtStream *w = wt_find(cn, stream_id);
  if (!w || w->rejected) return 0;
  int avail = w->rlen - w->roff;
  if (avail <= 0) return 0;
  int n = avail < cap ? avail : cap;
  memcpy(buf, w->rbuf + w->roff, n);
  w->roff += n;
  if (w->roff == w->rlen) { w->roff = 0; w->rlen = 0; }
  return n;
#else
  (void)c; (void)conn_token; (void)stream_id; (void)buf; (void)cap; return 0;
#endif
}

int aq_wt_stream_fin(aq_ctx *c, uint64_t conn_token, int64_t stream_id) {
#if AQ_WEBTRANSPORT
  Conn *cn = wt_conn(c, conn_token);
  if (!cn) return 0;
  WtStream *w = wt_find(cn, stream_id);
  /* "the peer finished" — only once everything it sent has been read out */
  if (w && w->fin && w->roff >= w->rlen) return 1;
#else
  (void)c; (void)conn_token; (void)stream_id;
#endif
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
  if (c->cli_body) free(c->cli_body);
  if (c->cred) gnutls_certificate_free_credentials(c->cred);
  if (c->fd >= 0) close(c->fd);
  free(c);
}
