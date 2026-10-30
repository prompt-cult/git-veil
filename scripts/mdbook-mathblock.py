#!/usr/bin/env python3
"""mdBook preprocessor: pull $$...$$ display-math blocks out of the chapter
markdown and stash them as raw HTML comments.

mdBook renders markdown with pulldown-cmark, whose CommonMark escape rules
mangle TeX inside a math block: the array row separators (`\\\\`) collapse to
`\\`, and `\\{`/`\\}` lose their braces, so the algorithm listings in
docs/src/design.md render on one line. This preprocessor replaces each `$$` block
with an HTML comment carrying the base64 of the full block. HTML comments pass
through the markdown renderer untouched; docs/tex-mj3.js decodes them back into
the page before MathJax typesets.

Wire protocol: mdBook passes a [context, book] array on stdin and expects the
Book object alone on stdout.
"""

import base64
import json
import re
import sys

MATH = re.compile(r"\$\$.+?\$\$", re.DOTALL)
PLACEHOLDER = "<!--gv-math:{}-->"


def stash(text: str) -> str:
    def repl(match: re.Match) -> str:
        encoded = base64.b64encode(match.group(0).encode("utf-8")).decode("ascii")
        return PLACEHOLDER.format(encoded)

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
