# serve

A high-level, programmable HTTP/1.1 server for
[Nimony](https://github.com/nim-lang/nimony) — the top of the `tcp → net → serve`
stack. Pairs the transport-free `http` helpers with the native `tcp` transport
(both re-exported). Pass a handler, return any `Response`; or drop in the built-in
static-file handler. Status-based, no framework runtime.

**📖 Full docs → [aoughwl.github.io/docs/net-stack](https://aoughwl.github.io/docs/net-stack)**

```nim
import serve

serve(8080, proc(req: Request): Response {.closure.} =
  ok("hello"))
```

Keep-alive, request-size cap (`413`), streamed responses (no truncation), slowloris
guard, path-traversal safety, and `staticHandler(root)` for static serving.
