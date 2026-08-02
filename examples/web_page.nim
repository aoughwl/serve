## web_page — serve a page built with the `web` DSL.
##
## The whole seam between presentation and transport: `document(…)` returns a
## complete HTML document as a string, and `response` sends it. Neither library
## depends on the other — `web` never imports a transport, `serve` never imports
## an HTML DSL — so this example is the only place they meet, which is the point.
##
##   nimony --path:. --path:../aoughwl-web --path:../aoughwl-html \
##          --path:../aoughwl-css c examples/web_page.nim
##
## Then open http://localhost:8080/.

import serve
import web

var sheet = initStylesheet()
sheet.rule ".card", declare("border", "1px solid #ddd") &
                    declare("border-radius", "8px") &
                    declare("padding", "16px")
useStylesheet sheet

component card(title: string, children: HTML):
  box:
    @class "card"
    h2 title
    children

component page(path: string):
  # A `web:` block cannot sit inside a call's parentheses, so the children are
  # bound first and passed by name.
  let intro = web:
    p "This page was built with the web DSL and served by serve."
  let body = card(title = "Hello from nimony", children = intro)

  box:
    @id "app"
    @style:                        # camelCase: `font-family` is not an ident
      fontFamily: "system-ui, sans-serif"
      maxWidth: 640.px
      margin: "40px auto"
    h1 "aoughwl"
    body
    p "you asked for " & path

proc handler(req: Request): Response {.nimcall.} =
  response(200, htmlContentType, document("aoughwl", page(path = req.path)))

when isMainModule:
  echo "serving on http://localhost:8080/"
  serve(8080, handler)
