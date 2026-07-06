## serve/tcp.aowl — small TCP abstraction used by `serve/loop`.
##
## The API is intentionally backend-shaped: listen, submit accept/read/write,
## wait for completions, close. Additional backends can be added here without
## changing the HTTP/static server.

import tcp_types
import tcp_ioring
export tcp_types
export tcp_ioring
