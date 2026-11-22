#!/usr/bin/env python3
"""mdBook preprocessor: pull $$...$$ display-math blocks out of the chapter
markdown and stash them as raw HTML comments plus a no-JS fallback.

mdBook renders markdown with pulldown-cmark, whose CommonMark escape rules
mangle TeX inside a math block: the array row separators (`\\\\`) collapse to
`\\`, and `\\{`/`\\}` lose their braces, so the algorithm listings in
docs/src/design.md render on one line. This preprocessor replaces each `$$` block
with TWO things, both build-time outputs, so the page is deterministic:

  1. An HTML comment carrying the base64 of the full block. HTML comments pass
     through the markdown renderer untouched; docs/tex-mj3.js decodes them back
     into the page before MathJax typesets (the JS path).
  2. A <noscript><pre> block with the math source as plain escaped text. The
     HTML spec defines noscript content as rendered exactly when scripting is
     disabled and inert otherwise, so JS readers get the MathJax SVG and
     no-JS readers (lynx, print without JS, LLM extraction, plain.txt) get
     the math as text instead of nothing.

Wire protocol: mdBook passes a [context, book] array on stdin and expects the
Book object alone on stdout.
"""

import base64
import html
import json
import re
import sys

MATH = re.compile(r"\$\$.+?\$\$", re.DOTALL)
PLACEHOLDER = "<!--gv-math:{}-->"


def stash(text: str) -> str:
    def repl(match: re.Match) -> str:
        tex = match.group(0)
        encoded = base64.b64encode(tex.encode("utf-8")).decode("ascii")
        # noscript content only renders when scripting is disabled; inside it
        # the TeX is plain escaped text in a pre, so line structure survives.
        fallback = "<noscript>\n<pre>" + html.escape(tex) + "</pre>\n</noscript>"
        return PLACEHOLDER.format(encoded) + "\n" + fallback

    return MATH.sub(repl, text)


def walk(node):
    if isinstance(node, list):
        for item in node:
            walk(item)
    elif isinstance(node, dict):
        if "content" in node and isinstance(node["content"], str):
            node["content"] = stash(node["content"])
        for value in node.values():
            walk(value)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "supports":
        sys.exit(0)
    context, book = json.load(sys.stdin)
    del context
    walk(book)
    json.dump(book, sys.stdout)


if __name__ == "__main__":
    main()
