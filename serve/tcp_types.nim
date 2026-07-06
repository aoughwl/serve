## serve/tcp_types.aowl — backend-neutral TCP transport types.

type
  TcpOp* = enum
    tcpRead, tcpWrite, tcpAccept

  TcpCompletion* = object
    op*: TcpOp
    fd*: cint
    result*: int
