## serve/tcp.aowl — small TCP abstraction used by `serve/loop`.
##
## The API is intentionally backend-shaped: listen, submit accept/read/write,
## wait for completions, close. The current backend is `tcp_ioring`; additional
## backends can be added here without changing the HTTP/static server.

import tcp_ioring
export tcp_ioring
